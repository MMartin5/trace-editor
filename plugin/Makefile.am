BABELTRACE_DIR = /home/mmartin/Bureau/Poly/Maîtrise/Outils/babeltrace-2.0.0-pre1

AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(BABELTRACE_DIR)/include -I$(BABELTRACE_DIR)/plugins

SUBDIRS = editor .

plugindir = "$(PLUGINSDIR)"
plugin_LTLIBRARIES = libbabeltrace-plugin-editor.la

libbabeltrace_plugin_text_la_SOURCES = plugin.c
libbabeltrace_plugin_text_la_LDFLAGS = \
	-version-info $(BABELTRACE_LIBRARY_VERSION)
libbabeltrace_plugin_text_la_LIBADD = \
	editor/libbabeltrace-plugin-trace-editor-cc.la

if !BUILT_IN_PLUGINS
libbabeltrace_plugin_editor_la_LIBADD += \
	$(top_builddir)/lib/libbabeltrace.la \
	$(top_builddir)/common/libbabeltrace-common.la
endif
