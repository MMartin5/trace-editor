#include "editor.h"
#include "editor-utils.c"

struct editor_component* create_editor_component() {
	struct editor_component* comp;

	comp = g_new0(struct editor_component, 1);

	writer_component->trace_name_base = g_string_new("ma-trace");
	writer_component->err = stderr;

	return comp;
}

enum bt_component_status editor_component_init(
	struct bt_private_component *component,
	struct bt_value *params, void *init_method_data) {
		enum bt_component_status ret;
		struct editor_component* editor;
		struct bt_value *value = NULL;
		enum bt_value_status value_ret;
		const char *path;

		editor = create_editor_component();

		ret = bt_private_component_sink_add_input_private_port(component,
			"in", NULL, NULL);

		value = bt_value_map_get(params, "path");
		value_ret = bt_value_string_get(value, &path);
		bt_put(value);
		editor->path = g_string_new(path);

		ret = bt_private_component_set_user_data(component, editor);

		return ret;
}

void editor_component_port_connected(
		struct bt_private_component *component,
		struct bt_private_port *self_port,
		struct bt_port *other_port) {

	struct bt_private_connection *connection;
	struct editor_component *editor;
	enum bt_connection_status conn_status;
	static const enum bt_notification_type notif_types[] = {
		BT_NOTIFICATION_TYPE_EVENT,
		BT_NOTIFICATION_TYPE_PACKET_BEGIN,
		BT_NOTIFICATION_TYPE_PACKET_END,
		BT_NOTIFICATION_TYPE_STREAM_BEGIN,
		BT_NOTIFICATION_TYPE_STREAM_END,
		BT_NOTIFICATION_TYPE_SENTINEL,
	};

	editor = bt_private_component_get_user_data(component);
	assert(editor);
	assert(!editor->input_iterator);
	connection = bt_private_port_get_private_connection(self_port);
	assert(connection);
	conn_status = bt_private_connection_create_notification_iterator(
		connection, notif_types, &editor->input_iterator);
	if (conn_status != BT_CONNECTION_STATUS_OK) {
		writer->error = true;
	}

	bt_put(connection);
}

void destroy_editor_component_data(struct editor_component *editor_component)
{
	bt_put(editor_component->input_iterator);

	// g_hash_table_foreach_remove(writer_component->trace_map,
	// 		empty_trace_map, writer_component);
	// g_hash_table_destroy(writer_component->trace_map);

	g_string_free(editor_component->path, true);
	g_string_free(editor_component->trace_name, true);
}

void finalize_editor(struct bt_private_component *component) {
	struct editor_component *editor_component = (struct editor_component *)
		bt_private_component_get_user_data(component);

	destroy_editor_component_data(editor_component);
	g_free(editor_component);
}

enum bt_component_status handle_notification(
		struct editor_component *editor_component,
		struct bt_notification *notification) {

	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;

	if (!editor_component) {
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	switch (bt_notification_get_type(notification)) {
	case BT_NOTIFICATION_TYPE_PACKET_BEGIN:
	{
		struct bt_ctf_packet *packet =
			bt_notification_packet_begin_get_packet(notification);

		if (!packet) {
			ret = BT_COMPONENT_STATUS_ERROR;
			goto end;
		}

		ret = editor_new_packet(editor_component, packet);
		bt_put(packet);
		break;
	}
	case BT_NOTIFICATION_TYPE_PACKET_END:
	{
		struct bt_ctf_packet *packet =
			bt_notification_packet_end_get_packet(notification);

		if (!packet) {
			ret = BT_COMPONENT_STATUS_ERROR;
			goto end;
		}
		ret = editor_close_packet(editor_component, packet);
		bt_put(packet);
		break;
	}
	case BT_NOTIFICATION_TYPE_EVENT:
	{
		struct bt_ctf_event *event = bt_notification_event_get_event(
				notification);

		if (!event) {
			ret = BT_COMPONENT_STATUS_ERROR;
			goto end;
		}
		ret = editor_output_event(editor_component, event);
		bt_put(event);
		if (ret != BT_COMPONENT_STATUS_OK) {
			goto end;
		}
		break;
	}
	case BT_NOTIFICATION_TYPE_STREAM_BEGIN:
	{
		struct bt_ctf_stream *stream =
			bt_notification_stream_begin_get_stream(notification);

		if (!stream) {
			ret = BT_COMPONENT_STATUS_ERROR;
			goto end;
		}
		ret = editor_stream_begin(editor_component, stream);
		bt_put(stream);
		break;
	}
	case BT_NOTIFICATION_TYPE_STREAM_END:
	{
		struct bt_ctf_stream *stream =
			bt_notification_stream_end_get_stream(notification);

		if (!stream) {
			ret = BT_COMPONENT_STATUS_ERROR;
			goto end;
		}
		ret = editor_stream_end(editor_component, stream);
		bt_put(stream);
		break;
	}
	default:
		puts("Unhandled notification type");
	}
end:
	return ret;
}

enum bt_component_status editor_run(struct bt_private_component *component) {
	enum bt_component_status ret;
	struct bt_notification *notification = NULL;
	struct bt_notification_iterator *it;
	struct writer_component *editor_component =
		bt_private_component_get_user_data(component);
	enum bt_notification_iterator_status it_ret;

	// if (unlikely(writer_component->error)) {
	// 	ret = BT_COMPONENT_STATUS_ERROR;
	// 	goto end;
	// }

	it = editor_component->input_iterator;
	assert(it);
	it_ret = bt_notification_iterator_next(it);

	switch (it_ret) {
	case BT_NOTIFICATION_ITERATOR_STATUS_END:
		ret = BT_COMPONENT_STATUS_END;
		BT_PUT(editor_component->input_iterator);
		goto end;
	case BT_NOTIFICATION_ITERATOR_STATUS_AGAIN:
		ret = BT_COMPONENT_STATUS_AGAIN;
		goto end;
	case BT_NOTIFICATION_ITERATOR_STATUS_OK:
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	notification = bt_notification_iterator_get_notification(it);
	assert(notification);
	ret = handle_notification(editor_component, notification);
end:
	bt_put(notification);
	return ret;
}
