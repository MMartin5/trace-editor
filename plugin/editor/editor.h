#ifndef BABELTRACE_PLUGINS_EDITOR_EDITOR_H
#define BABELTRACE_PLUGINS_EDITOR_EDITOR_H

enum bt_component_status editor_component_init(
	struct bt_private_component *component,
	struct bt_value *params, void *init_method_data);

void finalize_editor(struct bt_private_component *component);

#endif /* BABELTRACE_PLUGINS_EDITOR_EDITOR_H */
