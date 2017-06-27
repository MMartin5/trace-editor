#include <babeltrace/babeltrace.h>

int main(int argc, char *argv[])
{
  char *read_trace_path;
  char *write_trace_path;

  struct bt_context *ctx;
  int trace_id;
  struct bt_ctf_iter *iter;
  struct bt_ctf_event *ctf_event;

  struct bt_ctf_writer *writer;

  if (argv[1] == NULL || argv[2] == NULL) {
    printf("Missing arguments.\nUsage : ./test <path to trace to read from> <path to trace to write to>");
  }
  else {
    read_trace_path = argv[1];
    write_trace_path = argv[2];
  }

  return 0;
}
