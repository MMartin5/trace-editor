AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/include

SUBDIRS = editor

plugindir = "$(PLUGINSDIR)"
plugin_LTLIBRARIES = libbabeltrace-plugin-trace-editor.la

# editor plugin
libbabeltrace_plugin_trace_editor_la_SOURCES = plugin.c

libbabeltrace_plugin_trace_editor_la_LDFLAGS = \
	-version-info $(BABELTRACE_LIBRARY_VERSION)

libbabeltrace_plugin_trace_editor_la_LIBADD = \
	editor/libbabeltrace-plugin-editor.la

if !ENABLE_BUILT_IN_PLUGINS
libbabeltrace_plugin_trace_editor_la_LIBADD += \
	$(top_builddir)/lib/libbabeltrace.la \
	$(top_builddir)/logging/libbabeltrace-logging.la \
	$(top_builddir)/common/libbabeltrace-common.la
endif
