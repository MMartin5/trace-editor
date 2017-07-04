#include <babeltrace/plugin/plugin-dev.h>
#include "editor/editor.h"

/* plug-in description */
BT_PLUGIN(trace-editor);
BT_PLUGIN_DESCRIPTION("Trace editor");
BT_PLUGIN_AUTHOR("Marie Martin");
BT_PLUGIN_LICENSE("MIT");

/* editor component */
BT_PLUGIN_SINK_COMPONENT_CLASS(editor, editor_run);
BT_PLUGIN_SINK_COMPONENT_CLASS_DESCRIPTION(editor,
	"Read a trace, select some events to discard and some events to write to a new CTF trace.");
BT_PLUGIN_SINK_COMPONENT_CLASS_INIT_METHOD(editor, editor_component_init);
BT_PLUGIN_SINK_COMPONENT_CLASS_PORT_CONNECTED_METHOD(editor,
		editor_component_port_connected);
BT_PLUGIN_SINK_COMPONENT_CLASS_FINALIZE_METHOD(editor, finalize_editor);
