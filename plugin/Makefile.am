SUBDIRS = editor

plugindir = "$(PLUGINSDIR)"
plugin_LTLIBRARIES = babeltrace-plugin-trace-editor.la

# editor plugin
babeltrace_plugin_trace_editor_la_SOURCES = plugin.c

babeltrace_plugin_trace_editor_la_LDFLAGS = \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module

babeltrace_plugin_trace_editor_la_LIBADD = \
	editor/libbabeltrace-plugin-editor.la

if !ENABLE_BUILT_IN_PLUGINS
babeltrace_plugin_trace_editor_la_LIBADD += \
	$(top_builddir)/lib/libbabeltrace.la \
	$(top_builddir)/logging/libbabeltrace-logging.la \
	$(top_builddir)/common/libbabeltrace-common.la
endif
