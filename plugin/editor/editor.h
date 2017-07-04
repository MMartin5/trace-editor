#ifndef BABELTRACE_PLUGINS_EDITOR_EDITOR_H
#define BABELTRACE_PLUGINS_EDITOR_EDITOR_H

#include <stdbool.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/graph/component.h>
#include <babeltrace/ctf-writer/writer.h>

struct editor_component {
	GString *path;
	GString *trace_name;
	struct bt_notification_iterator *input_iterator;
	FILE *err;
	GHashTable *trace_map;
	bool error;
	int event_count;
	// int delete_index;
	GArray *delete_index;
};

enum fs_editor_stream_state {
	/*
	 * We know the stream exists but we have never received a
	 * stream_begin notification for it.
	 */
	FS_EDITOR_UNKNOWN_STREAM,
	/* We know this stream is active (between stream_begin and _end). */
	FS_EDITOR_ACTIVE_STREAM,
	/* We have received a stream_end for this stream. */
	FS_EDITOR_COMPLETED_STREAM,
};

struct fs_editor {
	struct bt_ctf_writer *writer;
	struct bt_ctf_trace *trace;
	struct bt_ctf_trace *writer_trace;
	struct editor_component *editor_component;
	int static_listener_id;
	int trace_static;
	/* Map between reader and writer stream. */
	GHashTable *stream_map;
	/* Map between reader and writer stream class. */
	GHashTable *stream_class_map;
	GHashTable *stream_states;
};

enum bt_component_status editor_component_init(
	struct bt_private_component *component,
	struct bt_value *params,
	void *init_method_data);

void editor_component_port_connected(
		struct bt_private_component *component,
		struct bt_private_port *self_port,
		struct bt_port *other_port);

enum bt_component_status editor_run(struct bt_private_component *component);

void finalize_editor(struct bt_private_component *component);

#endif /* BABELTRACE_PLUGINS_EDITOR_EDITOR_H */
