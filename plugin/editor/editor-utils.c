#define BT_LOG_TAG "PLUGIN-EDITOR"
#include "logging.h"

#include <babeltrace/babeltrace.h>
#include <assert.h>
#include <glib.h>
#include <babeltrace/ctf-ir/field-types-internal.h>
#include <babeltrace/ctf-ir/fields.h>
#include <babeltrace/ctf-ir/fields-internal.h>

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
	int ret;
	struct bt_ctf_stream *writer_stream = value;

	ret = bt_ctf_stream_flush(writer_stream);
	if (ret) {
		BT_LOGD_STR("Failed to flush stream while emptying hash table.");
	}
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
	struct bt_ctf_field_type *copy_packet_context_type = NULL;
	struct bt_ctf_field_type *begin_field_type = NULL;
	struct bt_ctf_field_type *end_field_type = NULL;
	struct bt_ctf_field_type *type = NULL;
	int ret_int;
	const char *name;
	// var used by ctf_copy_stream_class
	bool override_ts64 = true;
	FILE *err = editor_component->err;

	trace = bt_ctf_stream_class_get_trace(stream_class);
	assert(trace);

	writer_trace = bt_ctf_writer_get_trace(ctf_writer);
	assert(writer_trace);

	ret = ctf_copy_clock_classes(editor_component->err, writer_trace,
			writer_stream_class, trace);
	if (ret != BT_COMPONENT_STATUS_OK) {
		BT_LOGE_STR("Failed to copy clock classes.");
		goto error;
	}

	/* from ctf_copy_stream_class
	 * used to be ctf_copy_stream_class(editor_component->err, stream_class, writer_trace, true)
	 */
	name = bt_ctf_stream_class_get_name(stream_class);

	writer_stream_class = bt_ctf_stream_class_create_empty(name);
	assert(writer_stream_class);

	type = bt_ctf_stream_class_get_packet_context_type(stream_class);

	/* Add some modifications to the packet context type */

	// Prepare the fields type
	begin_field_type = bt_ctf_field_type_integer_create(64);
	if (!begin_field_type) {
		BT_LOGE_STR("Failed to create field type for lost_begin field.");
		goto error;
	}
	end_field_type = bt_ctf_field_type_integer_create(64);
	if (!end_field_type) {
		BT_LOGE_STR("Failed to create field type for lost_end field.");
		goto error;
	}

	copy_packet_context_type = bt_ctf_field_type_copy(type);	// get a new packet context type
	ret = bt_ctf_field_type_structure_add_field(copy_packet_context_type,
		begin_field_type, "lost_begin");	// add field "lost_begin" to new packet context type
	if (ret) {
		BT_LOGE_STR("Failed to add lost_begin field.");
		goto error;
	}
	ret = bt_ctf_field_type_structure_add_field(copy_packet_context_type,
		end_field_type, "lost_end");	// add field "lost_end" to new packet context type
	if (ret) {
		BT_LOGE_STR("Failed to add lost_end field.");
		goto error;
	}

	// Set the packet context type of the stream class
	bt_ctf_stream_class_set_packet_context_type(writer_stream_class, copy_packet_context_type);

	type = bt_ctf_stream_class_get_event_header_type(stream_class);
	if (type) {
		ret_int = bt_ctf_trace_get_clock_class_count(writer_trace);
		assert(ret_int >= 0);
		if (override_ts64 && ret_int > 0) {
			struct bt_ctf_field_type *new_event_header_type;

			new_event_header_type = override_header_type(err, type,
					writer_trace);
			if (!new_event_header_type) {
				BT_LOGE_STR("Failed to override header type.");
				goto error;
			}
			ret_int = bt_ctf_stream_class_set_event_header_type(
					writer_stream_class, new_event_header_type);
			BT_PUT(new_event_header_type);
			if (ret_int < 0) {
				BT_LOGE_STR("Failed to set event_header type.");
				goto error;
			}
		} else {
			ret_int = bt_ctf_stream_class_set_event_header_type(
					writer_stream_class, type);
			if (ret_int < 0) {
				BT_LOGE_STR("Failed to set event_header type.");
				goto error;
			}
		}
		BT_PUT(type);
	}

	type = bt_ctf_stream_class_get_event_context_type(stream_class);
	if (type) {
		ret_int = bt_ctf_stream_class_set_event_context_type(
				writer_stream_class, type);
		if (ret_int < 0) {
			BT_LOGE_STR("Failed to set event_contexttype.");
			goto error;
		}
	}
	BT_PUT(type);



	ret = bt_ctf_trace_add_stream_class(writer_trace, writer_stream_class);
	if (ret) {
		BT_LOGE_STR("Failed to add stream_class.");
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
		BT_LOGE_STR("Failed to allocate fs_writer_stream_state.");
		goto end;
	}
	*v = FS_EDITOR_UNKNOWN_STREAM;

	g_hash_table_insert(fs_editor->stream_states, stream, v);

end:
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

	/* Sanitize the trace name. */
	if (strlen(trace_name) == 2 && !strcmp(trace_name, "..")) {
		BT_LOGE_STR("Trace name cannot be \"..\".");
		goto error;
	}

	if (strstr(trace_name, "../")) {
		BT_LOGE_STR("Trace name cannot contain \"../\".");
		goto error;

	}

	snprintf(trace_path, PATH_MAX, "%s" G_DIR_SEPARATOR_S "%s",
			editor_component->path->str,
			trace_name);

		if (g_file_test(trace_path, G_FILE_TEST_EXISTS)) {
			int i = 0;

			do {
				snprintf(trace_path, PATH_MAX, "%s" G_DIR_SEPARATOR_S "%s-%d",
						editor_component->path->str,
						trace_name, ++i);
			} while (g_file_test(trace_path, G_FILE_TEST_EXISTS) && i < INT_MAX);
			if (i == INT_MAX) {
				BT_LOGE_STR("Unable to find a unique trace path.");
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
		BT_LOGE_STR("Failed to make trace path.");
		goto error;
	}

	printf("editor-trace.editor sink creating trace in %s\n", trace_path);

	ctf_writer = bt_ctf_writer_create(trace_path);
	if (!ctf_writer) {
		BT_LOGE_STR("Failed to create CTF editor.");
		goto error;
	}

	writer_trace = bt_ctf_writer_get_trace(ctf_writer);
	assert(writer_trace);

	ret = ctf_copy_trace(editor_component->err, trace, writer_trace);
	if (ret != BT_COMPONENT_STATUS_OK) {
		BT_LOGE_STR("Failed to copy trace.");
		BT_PUT(ctf_writer);
		goto error;
	}

	fs_editor = g_new0(struct fs_editor, 1);
	if (!fs_editor) {
		BT_LOGE_STR("Failed to allocate fs_writer.");
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
		assert(stream);

		insert_new_stream_state(editor_component, fs_editor, stream);
		BT_PUT(stream);
	}

	/* Check if the trace is already static or register a listener. */
	if (bt_ctf_trace_is_static(trace)) {
		fs_editor->trace_static = 1;
		fs_editor->static_listener_id = -1;
	} else {
		ret = bt_ctf_trace_add_is_static_listener(trace,
				trace_is_static_listener, NULL, fs_editor);
		assert(ret >= 0);
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
	assert(trace);

	fs_editor = g_hash_table_lookup(editor_component->trace_map,
			(gpointer) trace);
	if (!fs_editor) {
		fs_editor = insert_new_editor(editor_component, trace);
	}
	BT_PUT(trace);

	return fs_editor;
}

struct fs_editor *get_fs_editor_from_stream(
		struct editor_component *editor_component,
		struct bt_ctf_stream *stream)
{
	struct bt_ctf_stream_class *stream_class = NULL;
	struct fs_editor *fs_editor;

	stream_class = bt_ctf_stream_get_class(stream);
	assert(stream_class);

	fs_editor = get_fs_editor(editor_component, stream_class);

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

static
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
			BT_LOGE_STR("Failed to insert a new stream_class.");
			goto error;
		}
	}
	bt_get(writer_stream_class);

	writer_stream = bt_ctf_writer_create_stream(ctf_writer,
			writer_stream_class);
	assert(writer_stream);

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

static
struct bt_ctf_stream *get_writer_stream(
		struct editor_component *editor_component,
		struct bt_ctf_packet *packet,
    struct bt_ctf_stream *stream) {

	struct bt_ctf_stream *writer_stream = NULL;

	writer_stream = lookup_stream(editor_component, stream);
	if (!writer_stream) {
		BT_LOGE_STR("Failed to find existing stream.");
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
  assert(stream_class);

  fs_editor = get_fs_editor(editor_component, stream_class);
  if (!fs_editor) {
    BT_LOGE_STR("Failed to get fs_editor.");
    goto error;
  }

  /* Set the stream as active */
  state = g_hash_table_lookup(fs_editor->stream_states, stream);
  if (!state) {
    if (fs_editor->trace_static) {
      BT_LOGE_STR("Cannot add new stream on a static trace.");
      goto error;
    }
    state = insert_new_stream_state(editor_component, fs_editor,
        stream);
  }
  if (*state != FS_EDITOR_UNKNOWN_STREAM) {
    BT_LOGE("Unexpected stream state: state=%d", *state);
    goto error;
  }
  *state = FS_EDITOR_ACTIVE_STREAM;

  writer_stream = insert_new_stream(editor_component, fs_editor,
      stream_class, stream);
  if (!writer_stream) {
    BT_LOGE_STR("Failed to insert new stream.");
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
	assert(stream_class);

  fs_editor = get_fs_editor(editor_component, stream_class);
  if (!fs_editor) {
  	BT_LOGE_STR("Failed to get fs_writer.");
  	goto error;
  }

  state = g_hash_table_lookup(fs_editor->stream_states, stream);
  if (*state != FS_EDITOR_ACTIVE_STREAM) {
  	BT_LOGE("Unexpected stream state: state=%d", *state);
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
  	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
  	int int_ret;
		struct bt_ctf_field *packet_context = NULL, *writer_packet_context = NULL;
		struct bt_ctf_field *stream_packet_context = NULL;
		struct bt_ctf_field_type *stream_packet_context_type = NULL, *packet_context_type = NULL;
		struct bt_ctf_field *begin_field = NULL, *end_field = NULL;
		int fields_count = 0;
		char *field_name;
		struct bt_ctf_field_type *field_type;
		struct bt_ctf_field *field = NULL, *copy_field = NULL;

  	stream = bt_ctf_packet_get_stream(packet);
  	assert(stream);

  	writer_stream = get_writer_stream(editor_component, packet, stream);
  	if (!writer_stream) {
  		BT_LOGE_STR("Failed to get writer_stream.");
  		goto error;
  	}
  	BT_PUT(stream);

		/* from ctf_stream_copy_packet_context
		 * used to be ctf_stream_copy_packet_context(editor_component->err, packet, writer_stream);
		 */
		packet_context = bt_ctf_packet_get_context(packet);
		if (!packet_context) {
			goto end;
		}
		packet_context_type = bt_ctf_field_get_type(packet_context);

		stream_packet_context = bt_ctf_stream_get_packet_context(writer_stream);
		stream_packet_context_type = bt_ctf_field_get_type(stream_packet_context);
		writer_packet_context = bt_ctf_field_create(stream_packet_context_type);	// create a packet context from the new type
		if (!writer_packet_context) {
			BT_LOGE_STR("Failed to create field from stream packet context.");
			goto error;
		}

		// Copy every field from the old packet context
		fields_count = bt_ctf_field_type_structure_get_field_count(packet_context_type);
		for (int i = 0; i < fields_count; i++) {
			bt_ctf_field_type_structure_get_field_by_index(packet_context_type,
				&field_name, &field_type, i);	// get field name
			field = bt_ctf_field_structure_get_field_by_name(packet_context, field_name);	// get field from its name
			copy_field  = bt_ctf_field_copy(field);
			bt_ctf_field_structure_set_field_by_name(writer_packet_context, field_name,
				copy_field);	// set field in new packet context
		}

		// Initialize the new fields
		begin_field = bt_ctf_field_structure_get_field_by_name(writer_packet_context, "lost_begin");
		bt_ctf_field_unsigned_integer_set_value(begin_field, 0);
		end_field = bt_ctf_field_structure_get_field_by_name(writer_packet_context, "lost_end");
		bt_ctf_field_unsigned_integer_set_value(end_field, 0);

		ret = bt_ctf_stream_set_packet_context(writer_stream,
				writer_packet_context);
		if (ret) {
			BT_LOGE_STR("Failed to set stream packet context.");
			goto error;
		}

		ret = ctf_stream_copy_packet_header(editor_component->err,
				packet, writer_stream);
		if (ret != 0) {
			BT_LOGE_STR("Failed to copy packet_header.");
			goto error;
		}

  	goto end;

  error:
  	ret = BT_COMPONENT_STATUS_ERROR;
  end:
  	bt_put(writer_stream);
  	bt_put(stream);
		bt_put(packet_context);
		bt_put(writer_packet_context);
		bt_put(stream_packet_context);
		bt_put(stream_packet_context_type);
		bt_put(packet_context_type);
		bt_put(begin_field);
		bt_put(end_field);
		bt_put(field_type);
		bt_put(field);
  	return ret;
}

enum bt_component_status editor_close_packet(
		struct editor_component *editor_component,
		struct bt_ctf_packet *packet) {
  struct bt_ctf_stream *stream = NULL, *writer_stream = NULL;
  enum bt_component_status ret;

  stream = bt_ctf_packet_get_stream(packet);
  if (!stream) {
    assert(stream);
  }

  writer_stream = lookup_stream(editor_component, stream);
  if (!writer_stream) {
    BT_LOGE_STR("Failed to find existing stream.");
    goto error;
  }
  BT_PUT(stream);

  bt_get(writer_stream);

  ret = bt_ctf_stream_flush(writer_stream);
  if (ret < 0) {
    BT_LOGE_STR("Failed to flush stream.");
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
	assert(event_class);

  event_name = bt_ctf_event_class_get_name(event_class);
  if (!event_name) {
    fprintf(editor_component->err, "[error] %s in %s:%d\n", __func__,
        __FILE__, __LINE__);
    goto error;
  }

  stream = bt_ctf_event_get_stream(event);
  assert(stream);

  writer_stream = lookup_stream(editor_component, stream);
  if (!writer_stream || !bt_get(writer_stream)) {
    BT_LOGE_STR("Failed for find existing stream.");
    goto error;
  }

  stream_class = bt_ctf_event_class_get_stream_class(event_class);
  assert(stream_class);

  writer_stream_class = lookup_stream_class(editor_component, stream_class);
  if (!writer_stream_class || !bt_get(writer_stream_class)) {
    assert(stream_class);
    goto error;
  }

  writer_event_class = get_event_class(editor_component,
      writer_stream_class, event_class);
  if (!writer_event_class) {
    writer_event_class = ctf_copy_event_class(editor_component->err,
        event_class);
    if (!writer_event_class) {
      BT_LOGE_STR("Failed to copy event_class.");
      goto error;
    }
    int_ret = bt_ctf_stream_class_add_event_class(
        writer_stream_class, writer_event_class);
    if (int_ret) {
      BT_LOGE_STR("Failed to copy event_class.");
      goto error;
    }
  }

  writer_event = ctf_copy_event(editor_component->err, event,
      writer_event_class, true);
  if (!writer_event) {
    BT_LOGE("Failed to copy event: event_class=\"%s\"",
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

enum bt_component_status editor_add_lost_event(struct editor_component *editor_component) {

	enum bt_component_status ret;
	int int_ret;
  struct bt_ctf_stream *stream = NULL, *writer_stream = NULL;
	struct bt_ctf_field *packet_context = NULL, *copy_packet_context = NULL;
	struct bt_ctf_clock_value *clock_begin, *clock_end = NULL;
	uint64_t ts_begin, ts_end;
	struct bt_ctf_clock_class *clock_class = NULL;
	struct bt_ctf_field_type *begin_field_type = NULL;
	struct bt_ctf_field_type *end_field_type = NULL;
	struct bt_ctf_field *begin_field = NULL;
	struct bt_ctf_field *end_field = NULL;
	struct bt_ctf_field *field = NULL;

  stream = bt_ctf_event_get_stream(editor_component->first_event);
  assert(stream);

  writer_stream = lookup_stream(editor_component, stream);
  if (!writer_stream || !bt_get(writer_stream)) {
    BT_LOGE_STR("Failed for find existing stream.");
    goto error;
  }

	packet_context = bt_ctf_stream_get_packet_context(writer_stream);
	copy_packet_context = bt_ctf_field_copy(packet_context);	// get a new packet context

	// Get the required values
	clock_class = event_get_clock_class(editor_component->err, editor_component->first_event);
	clock_begin = bt_ctf_event_get_clock_value(editor_component->first_event, clock_class);
	bt_ctf_clock_value_get_value(clock_begin, &ts_begin);
	clock_end = bt_ctf_event_get_clock_value(editor_component->last_event, clock_class);
	bt_ctf_clock_value_get_value(clock_end, &ts_end);

	// Get field types from packet context
	field = bt_ctf_field_structure_get_field_by_name(copy_packet_context, "lost_begin");
	begin_field_type = bt_ctf_field_get_type(field);
	field = bt_ctf_field_structure_get_field_by_name(copy_packet_context, "lost_end");
	end_field_type = bt_ctf_field_get_type(field);

	// Set the new fields in the packet context with the retrieved values
	begin_field = bt_ctf_field_create(begin_field_type);
	bt_ctf_field_unsigned_integer_set_value(begin_field, ts_begin);
	end_field = bt_ctf_field_create(end_field_type);
	bt_ctf_field_unsigned_integer_set_value(end_field, ts_end);

	bt_ctf_field_structure_set_field_by_name(copy_packet_context, "lost_begin", begin_field);
	bt_ctf_field_structure_set_field_by_name(copy_packet_context, "lost_end", end_field);

	// Set the packet context of the stream
	bt_ctf_stream_set_packet_context(writer_stream, copy_packet_context);

	// Add deleted events counter to the existing count of discarded events
	bt_ctf_stream_append_discarded_events(writer_stream, editor_component->deleted_count);

	uint64_t count = 0;
	int_ret = bt_ctf_stream_get_discarded_events_count(writer_stream, &count);
	printf("\nLOST EVENTS COUNT NOW: %d", count);

  ret = BT_COMPONENT_STATUS_OK;
  goto end;

error:
  ret = BT_COMPONENT_STATUS_ERROR;
end:
  bt_put(writer_stream);
  bt_put(stream);
	bt_put(packet_context);
	bt_put(clock_class);
	bt_put(end_field_type);
	bt_put(begin_field_type);
	bt_put(clock_begin);
	bt_put(clock_end);
	bt_put(begin_field);
	bt_put(end_field);
	bt_put(copy_packet_context);
  return ret;
}
