#include <babeltrace/ctf-ir/event.h>
#include <babeltrace/ctf-ir/packet.h>
#include <babeltrace/ctf-ir/event-class.h>
#include <babeltrace/ctf-ir/stream.h>
#include <babeltrace/ctf-ir/stream-class.h>
#include <babeltrace/ctf-ir/clock-class.h>
#include <babeltrace/ctf-ir/fields.h>
#include <babeltrace/ctf-writer/stream-class.h>
#include <babeltrace/ctf-writer/stream.h>
#include <assert.h>

#include <ctfcopytrace.h>

#include "editor.h"

static
void unref_stream_class(struct bt_ctf_stream_class *writer_stream_class)
{
	bt_put(writer_stream_class);
}

static
void unref_stream(struct bt_ctf_stream_class *writer_stream)
{
	bt_put(writer_stream);
}

static
gboolean empty_ht(gpointer key, gpointer value, gpointer user_data)
{
	return TRUE;
}

static
gboolean empty_streams_ht(gpointer key, gpointer value, gpointer user_data)
{
	struct bt_ctf_stream *writer_stream = value;

	bt_ctf_stream_flush(writer_stream);

	return TRUE;
}

static
void destroy_stream_state_key(gpointer key)
{
	g_free((enum fs_editor_stream_state *) key);
}

static
void check_completed_trace(gpointer key, gpointer value, gpointer user_data)
{
	enum fs_editor_stream_state *state = value;
	int *trace_completed = user_data;

	if (*state != FS_EDITOR_COMPLETED_STREAM) {
		*trace_completed = 0;
	}
}

static
void trace_is_static_listener(struct bt_ctf_trace *trace, void *data)
{
	struct fs_editor *fs_editor = data;
	int trace_completed = 1;

	fs_editor->trace_static = 1;

	g_hash_table_foreach(fs_editor->stream_states,
			check_completed_trace, &trace_completed);
	if (trace_completed) {
		editor_close(fs_editor->editor_component, fs_editor);
		g_hash_table_remove(fs_editor->editor_component->trace_map,
				fs_editor->trace);
	}
}

static
struct bt_ctf_stream_class *insert_new_stream_class(
		struct editor_component *editor_component,
		struct fs_editor *fs_editor,
		struct bt_ctf_stream_class *stream_class)
{
	struct bt_ctf_stream_class *writer_stream_class = NULL;
	struct bt_ctf_trace *trace = NULL, *writer_trace = NULL;
	struct bt_ctf_writer *ctf_writer = fs_editor->writer;
	enum bt_component_status ret;

	trace = bt_ctf_stream_class_get_trace(stream_class);
	if (!trace) {
		fprintf(editor_component->err,
				"[error] %s in %s:%d\n", __func__, __FILE__,
				__LINE__);
		goto error;
	}

	writer_trace = bt_ctf_writer_get_trace(ctf_writer);
	if (!writer_trace) {
		fprintf(editor_component->err,
				"[error] %s in %s:%d\n", __func__, __FILE__,
				__LINE__);
		goto error;
	}

	ret = ctf_copy_clock_classes(editor_component->err, writer_trace,
			writer_stream_class, trace);
	if (ret != BT_COMPONENT_STATUS_OK) {
		fprintf(editor_component->err,
				"[error] %s in %s:%d\n", __func__, __FILE__,
				__LINE__);
		goto error;
	}

	writer_stream_class = ctf_copy_stream_class(editor_component->err,
			stream_class, writer_trace, true);
	if (!writer_stream_class) {
		fprintf(editor_component->err, "[error] Failed to copy stream class\n");
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}

	g_hash_table_insert(fs_editor->stream_class_map,
			(gpointer) stream_class, writer_stream_class);

	goto end;

error:
	BT_PUT(writer_stream_class);
end:
	bt_put(writer_trace);
	bt_put(trace);
	return writer_stream_class;
}

static
enum fs_editor_stream_state *insert_new_stream_state(
		struct editor_component *editor_component,
		struct fs_editor *fs_editor, struct bt_ctf_stream *stream)
{
	enum fs_editor_stream_state *v = NULL;

	v = g_new0(enum fs_editor_stream_state, 1);
	if (!v) {
		fprintf(editor_component->err,
				"[error] %s in %s:%d\n", __func__,
				__FILE__, __LINE__);
	}
	*v = FS_EDITOR_UNKNOWN_STREAM;

	g_hash_table_insert(fs_editor->stream_states, stream, v);

	return v;
}

static
int make_trace_path(struct editor_component *editor_component,
		struct bt_ctf_trace *trace, char *trace_path)
{
	int ret;
	const char *trace_name;

	trace_name = bt_ctf_trace_get_name(trace);
	if (!trace_name) {
		trace_name = editor_component->trace_name->str;
	}
	/* XXX: we might have to skip the first level, TBD. */

	/* Sanitize the trace name. */
	if (strlen(trace_name) == 2 && !strcmp(trace_name, "..")) {
		fprintf(editor_component->err, "[error] Trace name cannot "
				"be \"..\"\n");
		goto error;
	}

	if (strstr(trace_name, "../")) {
		fprintf(editor_component->err, "[error] Trace name cannot "
				"contain \"../\", received \"%s\"\n",
				trace_name);
		goto error;

	}

	snprintf(trace_path, PATH_MAX, "%s/%s",
			editor_component->path->str,
			trace_name);
	if (g_file_test(trace_path, G_FILE_TEST_EXISTS)) {
		int i = 0;
		do {
			snprintf(trace_path, PATH_MAX, "%s/%s-%d",
					editor_component->path->str,
					trace_name, ++i);
		} while (g_file_test(trace_path, G_FILE_TEST_EXISTS) && i < INT_MAX);
		if (i == INT_MAX) {
			fprintf(editor_component->err, "[error] Unable to find "
					"a unique trace path\n");
			goto error;
		}
	}

	ret = 0;

	goto end;

error:
	ret = -1;
end:
	return ret;
}

static
struct fs_editor *insert_new_editor(
		struct editor_component *editor_component,
		struct bt_ctf_trace *trace)
{
	struct bt_ctf_writer *ctf_writer = NULL;
	struct bt_ctf_trace *writer_trace = NULL;
	char trace_path[PATH_MAX];
	enum bt_component_status ret;
	struct bt_ctf_stream *stream = NULL;
	struct fs_editor *fs_editor = NULL;
	int nr_stream, i;

	ret = make_trace_path(editor_component, trace, trace_path);
	if (ret) {
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}

	printf("editor-trace.editor sink creating trace in %s\n", trace_path);

	ctf_writer = bt_ctf_writer_create(trace_path);
	if (!ctf_writer) {
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}

	writer_trace = bt_ctf_writer_get_trace(ctf_writer);
	if (!writer_trace) {
		fprintf(editor_component->err,
				"[error] %s in %s:%d\n", __func__, __FILE__,
				__LINE__);
		goto error;
	}

	ret = ctf_copy_trace(editor_component->err, trace, writer_trace);
	if (ret != BT_COMPONENT_STATUS_OK) {
		fprintf(editor_component->err, "[error] Failed to copy trace\n");
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		BT_PUT(ctf_writer);
		goto error;
	}

	fs_editor = g_new0(struct fs_editor, 1);
	if (!fs_editor) {
		fprintf(editor_component->err,
				"[error] %s in %s:%d\n", __func__, __FILE__,
				__LINE__);
		goto error;
	}
	fs_editor->writer = ctf_writer;
	fs_editor->trace = trace;
	fs_editor->writer_trace = writer_trace;
	fs_editor->editor_component = editor_component;
	BT_PUT(writer_trace);
	fs_editor->stream_class_map = g_hash_table_new_full(g_direct_hash,
			g_direct_equal, NULL, (GDestroyNotify) unref_stream_class);
	fs_editor->stream_map = g_hash_table_new_full(g_direct_hash,
			g_direct_equal, NULL, (GDestroyNotify) unref_stream);
	fs_editor->stream_states = g_hash_table_new_full(g_direct_hash,
			g_direct_equal, NULL, destroy_stream_state_key);

	/* Set all the existing streams in the unknown state. */
	nr_stream = bt_ctf_trace_get_stream_count(trace);
	for (i = 0; i < nr_stream; i++) {
		stream = bt_ctf_trace_get_stream_by_index(trace, i);
		if (!stream) {
			fprintf(editor_component->err,
					"[error] %s in %s:%d\n", __func__,
					__FILE__, __LINE__);
			goto error;
		}
		insert_new_stream_state(editor_component, fs_editor, stream);
		BT_PUT(stream);
	}

	/* Check if the trace is already static or register a listener. */
	if (bt_ctf_trace_is_static(trace)) {
		fs_editor->trace_static = 1;
		fs_editor->static_listener_id = -1;
	} else {
		ret = bt_ctf_trace_add_is_static_listener(trace,
				trace_is_static_listener, fs_editor);
		if (ret < 0) {
			fprintf(editor_component->err,
					"[error] %s in %s:%d\n", __func__, __FILE__,
					__LINE__);
			goto error;
		}
		fs_editor->static_listener_id = ret;
	}

	g_hash_table_insert(editor_component->trace_map, (gpointer) trace,
			fs_editor);

	goto end;

error:
	g_free(fs_editor);
	fs_editor = NULL;
	bt_put(writer_trace);
	bt_put(stream);
	BT_PUT(ctf_writer);
end:
	return fs_editor;
}

struct fs_editor *get_fs_editor(struct editor_component *editor_component,
		struct bt_ctf_stream_class *stream_class)
{
	struct bt_ctf_trace *trace = NULL;
	struct fs_editor *fs_editor;

	trace = bt_ctf_stream_class_get_trace(stream_class);
	if (!trace) {
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}

	fs_editor = g_hash_table_lookup(editor_component->trace_map,
			(gpointer) trace);
	if (!fs_editor) {
		fs_editor = insert_new_editor(editor_component, trace);
	}
	BT_PUT(trace);
	goto end;

error:
	fs_editor = NULL;
end:
	return fs_editor;
}

struct fs_editor *get_fs_editor_from_stream(
		struct editor_component *editor_component,
		struct bt_ctf_stream *stream)
{
	struct bt_ctf_stream_class *stream_class = NULL;
	struct fs_editor *fs_editor;

	stream_class = bt_ctf_stream_get_class(stream);
	if (!stream_class) {
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}

	fs_editor = get_fs_editor(editor_component, stream_class);
	goto end;

error:
	fs_editor = NULL;

end:
	bt_put(stream_class);
	return fs_editor;
}

static
struct bt_ctf_stream_class *lookup_stream_class(
		struct editor_component *editor_component,
		struct bt_ctf_stream_class *stream_class)
{
	struct fs_editor *fs_editor = get_fs_editor(
			editor_component, stream_class);
	assert(fs_editor);
	return (struct bt_ctf_stream_class *) g_hash_table_lookup(
			fs_editor->stream_class_map, (gpointer) stream_class);
}

struct bt_ctf_stream *lookup_stream(struct editor_component *editor_component,
		struct bt_ctf_stream *stream)
{
	struct fs_editor *fs_editor = get_fs_editor_from_stream(
			editor_component, stream);
	assert(fs_editor);
	return (struct bt_ctf_stream *) g_hash_table_lookup(
			fs_editor->stream_map, (gpointer) stream);
}

static
struct bt_ctf_stream *insert_new_stream(
		struct editor_component *editor_component,
		struct fs_editor *fs_editor,
		struct bt_ctf_stream_class *stream_class,
		struct bt_ctf_stream *stream)
{
	struct bt_ctf_stream *writer_stream = NULL;
	struct bt_ctf_stream_class *writer_stream_class = NULL;
	struct bt_ctf_writer *ctf_writer = bt_get(fs_editor->writer);

	writer_stream_class = lookup_stream_class(editor_component,
			stream_class);
	if (!writer_stream_class) {
		writer_stream_class = insert_new_stream_class(
				editor_component, fs_editor, stream_class);
		if (!writer_stream_class) {
			fprintf(editor_component->err, "[error] %s in %s:%d\n",
					__func__, __FILE__, __LINE__);
			goto error;
		}
	}
	bt_get(writer_stream_class);

	writer_stream = bt_ctf_writer_create_stream(ctf_writer,
			writer_stream_class);
	if (!writer_stream) {
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}

	g_hash_table_insert(fs_editor->stream_map, (gpointer) stream,
			writer_stream);

	goto end;

error:
	BT_PUT(writer_stream);
end:
	bt_put(ctf_writer);
	bt_put(writer_stream_class);
	return writer_stream;
}

static
struct bt_ctf_event_class *get_event_class(struct editor_component *editor_component,
		struct bt_ctf_stream_class *writer_stream_class,
		struct bt_ctf_event_class *event_class)
{
	return bt_ctf_stream_class_get_event_class_by_id(writer_stream_class,
			bt_ctf_event_class_get_id(event_class));
}

struct bt_ctf_stream *get_writer_stream(
		struct editor_component *editor_component,
		struct bt_ctf_packet *packet,
    struct bt_ctf_stream *stream) {

	struct bt_ctf_stream *writer_stream = NULL;

	writer_stream = lookup_stream(editor_component, stream);
	if (!writer_stream) {
		fprintf(editor_component->err, "[error] %s in %s:%d\n",
				__func__, __FILE__, __LINE__);
		goto error;
	}
	bt_get(writer_stream);

	goto end;

error:
	BT_PUT(writer_stream);
end:
	return writer_stream;
}

void editor_close(struct editor_component *editor_component,
		struct fs_editor *fs_editor)
{
	if (fs_editor->static_listener_id >= 0) {
		bt_ctf_trace_remove_is_static_listener(fs_editor->trace,
				fs_editor->static_listener_id);
	}

	/* Empty the stream class HT. */
	g_hash_table_foreach_remove(fs_editor->stream_class_map,
			empty_ht, NULL);
	g_hash_table_destroy(fs_editor->stream_class_map);

	/* Empty the stream HT. */
	g_hash_table_foreach_remove(fs_editor->stream_map,
			empty_streams_ht, NULL);
	g_hash_table_destroy(fs_editor->stream_map);

	/* Empty the stream state HT. */
	g_hash_table_foreach_remove(fs_editor->stream_states,
			empty_ht, NULL);
	g_hash_table_destroy(fs_editor->stream_states);
}

enum bt_component_status editor_stream_begin(
		struct editor_component *editor_component,
		struct bt_ctf_stream *stream) {
  struct bt_ctf_stream_class *stream_class = NULL;
  struct fs_editor *fs_editor;
  struct bt_ctf_stream *writer_stream = NULL;
  enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
  enum fs_editor_stream_state *state;

  stream_class = bt_ctf_stream_get_class(stream);
  if (!stream_class) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n",
        __func__, __FILE__, __LINE__);
    goto error;
  }

  fs_editor = get_fs_editor(editor_component, stream_class);
  if (!fs_editor) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n",
        __func__, __FILE__, __LINE__);
    goto error;
  }

  /* Set the stream as active */
  state = g_hash_table_lookup(fs_editor->stream_states, stream);
  if (!state) {
    if (fs_editor->trace_static) {
      fprintf(editor_component->err, "[error] Adding a new "
          "stream on a static trace\n");
      goto error;
    }
    state = insert_new_stream_state(editor_component, fs_editor,
        stream);
  }
  if (*state != FS_EDITOR_UNKNOWN_STREAM) {
    fprintf(editor_component->err, "[error] Unexpected stream "
        "state %d\n", *state);
    goto error;
  }
  *state = FS_EDITOR_ACTIVE_STREAM;

  writer_stream = insert_new_stream(editor_component, fs_editor,
      stream_class, stream);
  if (!writer_stream) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n",
        __func__, __FILE__, __LINE__);
    goto error;
  }

  goto end;

  error:
  ret = BT_COMPONENT_STATUS_ERROR;
  end:
  bt_put(stream_class);
  return ret;
}

enum bt_component_status editor_stream_end(
		struct editor_component *editor_component,
		struct bt_ctf_stream *stream) {
  struct bt_ctf_stream_class *stream_class = NULL;
  struct fs_editor *fs_editor;
  struct bt_ctf_trace *trace = NULL;
  enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
  enum fs_editor_stream_state *state;

  stream_class = bt_ctf_stream_get_class(stream);
  if (!stream_class) {
  	fprintf(editor_component->err, "[error] %s in %s:%d\n",
  			__func__, __FILE__, __LINE__);
  	goto error;
  }

  fs_editor = get_fs_editor(editor_component, stream_class);
  if (!fs_editor) {
  	fprintf(editor_component->err, "[error] %s in %s:%d\n",
  			__func__, __FILE__, __LINE__);
  	goto error;
  }

  state = g_hash_table_lookup(fs_editor->stream_states, stream);
  if (*state != FS_EDITOR_ACTIVE_STREAM) {
  	fprintf(editor_component->err, "[error] Unexpected stream "
  			"state %d\n", *state);
  	goto error;
  }
  *state = FS_EDITOR_COMPLETED_STREAM;

  g_hash_table_remove(fs_editor->stream_map, stream);

  if (fs_editor->trace_static) {
  	int trace_completed = 1;

  	g_hash_table_foreach(fs_editor->stream_states,
  			check_completed_trace, &trace_completed);
  	if (trace_completed) {
  		editor_close(editor_component, fs_editor);
  		g_hash_table_remove(editor_component->trace_map,
  				fs_editor->trace);
  	}
  }

  goto end;

  error:
  ret = BT_COMPONENT_STATUS_ERROR;
  end:
  BT_PUT(trace);
  BT_PUT(stream_class);
  return ret;
}

enum bt_component_status editor_new_packet(
		struct editor_component *editor_component,
		struct bt_ctf_packet *packet) {

    struct bt_ctf_stream *stream = NULL, *writer_stream = NULL;
  	struct bt_ctf_field *writer_packet_context = NULL;
  	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
  	int int_ret;

  	stream = bt_ctf_packet_get_stream(packet);
  	if (!stream) {
  		fprintf(editor_component->err, "[error] %s in %s:%d\n",
  				__func__, __FILE__, __LINE__);
  		goto error;
  	}

  	writer_stream = get_writer_stream(editor_component, packet, stream);
  	if (!writer_stream) {
  		fprintf(editor_component->err, "[error] %s in %s:%d\n",
  				__func__, __FILE__, __LINE__);
  		goto error;
  	}
  	BT_PUT(stream);

  	writer_packet_context = ctf_copy_packet_context(editor_component->err,
  			packet, writer_stream);
  	if (!writer_packet_context) {
  		fprintf(editor_component->err, "[error] %s in %s:%d\n",
  				__func__, __FILE__, __LINE__);
  		goto error;
  	}

  	int_ret = bt_ctf_stream_set_packet_context(writer_stream,
  			writer_packet_context);
  	if (int_ret < 0) {
  		fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
  				__FILE__, __LINE__);
  		goto error;
  	}
  	BT_PUT(writer_stream);
  	BT_PUT(writer_packet_context);

  	goto end;

  error:
  	ret = BT_COMPONENT_STATUS_ERROR;
  end:
  	bt_put(writer_stream);
  	bt_put(writer_packet_context);
  	bt_put(stream);
  	return ret;
}

enum bt_component_status editor_close_packet(
		struct editor_component *editor_component,
		struct bt_ctf_packet *packet) {
  struct bt_ctf_stream *stream = NULL, *writer_stream = NULL;
  enum bt_component_status ret;

  stream = bt_ctf_packet_get_stream(packet);
  if (!stream) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n",
        __func__, __FILE__, __LINE__);
    goto error;
  }

  writer_stream = lookup_stream(editor_component, stream);
  if (!writer_stream) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n",
        __func__, __FILE__, __LINE__);
    goto error;
  }
  BT_PUT(stream);

  bt_get(writer_stream);

  ret = bt_ctf_stream_flush(writer_stream);
  if (ret < 0) {
    fprintf(editor_component->err,
        "[error] Failed to flush packet\n");
    goto error;
  }
  BT_PUT(writer_stream);

  ret = BT_COMPONENT_STATUS_OK;
  goto end;

  error:
  ret = BT_COMPONENT_STATUS_ERROR;
  end:
  bt_put(writer_stream);
  bt_put(stream);
  return ret;
}

enum bt_component_status editor_output_event(
		struct editor_component *editor_component,
		struct bt_ctf_event *event) {
  enum bt_component_status ret;
  struct bt_ctf_event_class *event_class = NULL, *writer_event_class = NULL;
  struct bt_ctf_stream *stream = NULL, *writer_stream = NULL;
  struct bt_ctf_stream_class *stream_class = NULL, *writer_stream_class = NULL;
  struct bt_ctf_event *writer_event = NULL;
  const char *event_name;
  int int_ret;

  event_class = bt_ctf_event_get_class(event);
  if (!event_class) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  event_name = bt_ctf_event_class_get_name(event_class);
  if (!event_name) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  stream = bt_ctf_event_get_stream(event);
  if (!stream) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  writer_stream = lookup_stream(editor_component, stream);
  if (!writer_stream || !bt_get(writer_stream)) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  stream_class = bt_ctf_event_class_get_stream_class(event_class);
  if (!stream_class) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  writer_stream_class = lookup_stream_class(editor_component, stream_class);
  if (!writer_stream_class || !bt_get(writer_stream_class)) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  writer_event_class = get_event_class(editor_component,
      writer_stream_class, event_class);
  if (!writer_event_class) {
    writer_event_class = ctf_copy_event_class(editor_component->err,
        event_class);
    if (!writer_event_class) {
      fprintf(editor_component->err, "[error] %s in %s:%d\n",
          __func__, __FILE__, __LINE__);
      goto error;
    }
    int_ret = bt_ctf_stream_class_add_event_class(
        writer_stream_class, writer_event_class);
    if (int_ret) {
      fprintf(editor_component->err, "[error] %s in %s:%d\n",
          __func__, __FILE__, __LINE__);
      goto error;
    }
  }

  writer_event = ctf_copy_event(editor_component->err, event,
      writer_event_class, true);
  if (!writer_event) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    fprintf(editor_component->err, "[error] Failed to copy event %s\n",
        bt_ctf_event_class_get_name(writer_event_class));
    goto error;
  }

  int_ret = bt_ctf_stream_append_event(writer_stream, writer_event);
  if (int_ret < 0) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    fprintf(editor_component->err, "[error] Failed to append event %s\n",
        bt_ctf_event_class_get_name(writer_event_class));
    goto error;
  }

  ret = BT_COMPONENT_STATUS_OK;
  goto end;

  error:
  ret = BT_COMPONENT_STATUS_ERROR;
  end:
  bt_put(writer_event);
  bt_put(writer_event_class);
  bt_put(writer_stream_class);
  bt_put(stream_class);
  bt_put(writer_stream);
  bt_put(stream);
  bt_put(event_class);
  return ret;
}
