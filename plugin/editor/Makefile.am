AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/include -I$(top_srcdir)/plugins \
	-I$(top_srcdir)/plugins/libctfcopytrace `pkg-config --cflags glib-2.0`

noinst_LTLIBRARIES = libbabeltrace-plugin-editor.la

libbabeltrace_plugin_editor_la_LIBADD =

# editor plugin
libbabeltrace_plugin_editor_la_SOURCES = \
	editor.c \
	editor.h \
	editor-utils.c

if !ENABLE_BUILT_IN_PLUGINS
libbabeltrace_plugin_editor_la_LIBADD += \
	$(top_builddir)/plugins/libctfcopytrace/libctfcopytrace.la
endif
