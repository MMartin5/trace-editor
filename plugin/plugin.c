#include <babeltrace/plugin/plugin-dev.h>
#include "editor/editor.h"

BT_PLUGIN(editor);
BT_PLUGIN_DESCRIPTION("Trace editor");
BT_PLUGIN_AUTHOR("Marie Martin");
BT_PLUGIN_LICENSE("MIT");

/* editor filter */
BT_PLUGIN_FILTER_COMPONENT_CLASS(editor, editor_iterator_next);
BT_PLUGIN_FILTER_COMPONENT_CLASS_DESCRIPTION(editor,
	"Select some events to discard and some events to write to a new trace.");
BT_PLUGIN_FILTER_COMPONENT_CLASS_INIT_METHOD(editor, editor_component_init);
BT_PLUGIN_FILTER_COMPONENT_CLASS_FINALIZE_METHOD(editor, finalize_editor);
BT_PLUGIN_FILTER_COMPONENT_CLASS_NOTIFICATION_ITERATOR_INIT_METHOD(editor,
	editor_iterator_init);
BT_PLUGIN_FILTER_COMPONENT_CLASS_NOTIFICATION_ITERATOR_FINALIZE_METHOD(editor,
	editor_iterator_finalize);
BT_PLUGIN_FILTER_COMPONENT_CLASS_NOTIFICATION_ITERATOR_SEEK_TIME_METHOD(editor,
	editor_iterator_seek_time);
