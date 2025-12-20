// SPDX-License-Identifier: GPL-2.0
#include "builtin.h"
#include "util/data.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/evsel.h"
#include "util/evlist.h"
#include "util/machine.h"
#include "util/thread.h"
#include "util/map.h"
#include "util/symbol.h"
#include "util/dso.h"
#include "util/hist.h"
#include "util/sort.h"
#include "util/annotate.h"
#include "util/annotate-data.h"
#include "util/debug.h"
#include "util/env.h"
#include "util/event.h"
#include "ui/ui.h"

#include <subcmd/parse-options.h>
#include <linux/err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *input_name = "perf.data";
static bool verbose_mode;
static bool show_all_samples;

static struct {
	u64 total_samples;
	u64 samples_with_symbols;
	u64 samples_with_data_types;
	u64 mmap_events;
	u64 comm_events;
	u64 fork_events;
	u64 exit_events;
} stats;

struct data_reader {
	struct perf_tool tool;
	struct perf_session *session;
};

static int process_mmap_event(const struct perf_tool *tool,
			      union perf_event *event,
			      struct perf_sample *sample,
			      struct machine *machine)
{
	stats.mmap_events++;
	return perf_event__process_mmap(tool, event, sample, machine);
}

static int process_mmap2_event(const struct perf_tool *tool,
			       union perf_event *event,
			       struct perf_sample *sample,
			       struct machine *machine)
{
	stats.mmap_events++;
	return perf_event__process_mmap2(tool, event, sample, machine);
}

static int process_comm_event(const struct perf_tool *tool,
			      union perf_event *event,
			      struct perf_sample *sample,
			      struct machine *machine)
{
	stats.comm_events++;
	return perf_event__process_comm(tool, event, sample, machine);
}

static int process_fork_event(const struct perf_tool *tool,
			      union perf_event *event,
			      struct perf_sample *sample,
			      struct machine *machine)
{
	stats.fork_events++;
	return perf_event__process_fork(tool, event, sample, machine);
}

static int process_exit_event(const struct perf_tool *tool,
			      union perf_event *event,
			      struct perf_sample *sample,
			      struct machine *machine)
{
	stats.exit_events++;
	return perf_event__process_exit(tool, event, sample, machine);
}

static int evsel__add_sample(struct evsel *evsel, struct perf_sample *sample,
			     struct addr_location *al)
{
	struct hists *hists = evsel__hists(evsel);
	struct hist_entry *he;


	he = hists__add_entry(hists, al, NULL, NULL, NULL, NULL, sample, true);
	if (he == NULL)
		return -ENOMEM;

	hists__inc_nr_samples(hists, true);
	return 0;
}

static int process_sample_event(const struct perf_tool *tool __maybe_unused,
				union perf_event *event,
				struct perf_sample *sample,
				struct evsel *evsel,
				struct machine *machine)
{
	struct addr_location al;
	int ret = 0;
	u8 cpumode;

	stats.total_samples++;

	cpumode = event->header.misc & PERF_RECORD_MISC_CPUMODE_MASK;
	if (cpumode != PERF_RECORD_MISC_USER)
		return 0;

	addr_location__init(&al);
	if (machine__resolve(machine, &al, sample) < 0) {
		pr_warning("problem processing %d event, skipping it.\n",
			   event->header.type);
		ret = -1;
		goto out_put;
	}

	if (verbose_mode) {
		pr_info("SAMPLE event: ip=0x%llx, period=%llu, sym=%s\n",
			(unsigned long long)sample->ip,
			(unsigned long long)sample->period,
			al.sym ? al.sym->name : "[unknown]");
	}

	if (!al.filtered && evsel__add_sample(evsel, sample, &al)) {
		pr_warning("problem incrementing symbol count, skipping event\n");
		ret = -1;
	}

	if (al.sym)
		stats.samples_with_symbols++;

out_put:
	addr_location__exit(&al);
	return ret;
}

static void print_statistics(void)
{
	printf("\n");
	printf("=== Processing Statistics ===\n");
	printf("Total samples:           %" PRIu64 "\n", stats.total_samples);
	printf("  With symbols:          %" PRIu64 " (%.1f%%)\n",
	       stats.samples_with_symbols,
	       stats.total_samples ? 100.0 * stats.samples_with_symbols / stats.total_samples : 0);

	printf("\n");
	printf("Other events:\n");
	printf("  MMAP:                  %" PRIu64 "\n", stats.mmap_events);
	printf("  COMM:                  %" PRIu64 "\n", stats.comm_events);
	printf("  FORK:                  %" PRIu64 "\n", stats.fork_events);
	printf("  EXIT:                  %" PRIu64 "\n", stats.exit_events);
	printf("\n");
}

static void print_hist_entries(struct perf_session *session)
{
	struct evsel *evsel;

	printf("\n=== Histogram Entries ===\n");

	evlist__for_each_entry(session->evlist, evsel) {
		struct hists *hists = evsel__hists(evsel);
		struct rb_node *nd;
		int entry_num = 0;

		if (hists->stats.nr_samples == 0)
			continue;

		hists__collapse_resort(hists, NULL);
		evsel__output_resort(evsel, NULL);

		printf("\nEvent: %s\n", evsel__name(evsel));
		printf("%-5s %-30s %12s %12s\n", "Entry", "Symbol", "Samples", "Period");
		printf("-------------------------------------------------------------\n");

		for (nd = rb_first_cached(&hists->entries); nd; nd = rb_next(nd)) {
			struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
			const char *sym_name = he->ms.sym ? he->ms.sym->name : "[unknown]";

			printf("%-5d %-30s %12llu %12llu\n",
			       ++entry_num, sym_name,
			       (unsigned long long)he->stat.nr_events,
			       (unsigned long long)he->stat.period);
		}

		if (entry_num == 0)
			printf("  (no entries)\n");
	}

	printf("\n");
}

static int __cmd_data_reader(struct data_reader *dr)
{
	int err;

	printf("Reading: %s\n", input_name);

	printf("Hostname:     %s\n", perf_session__env(dr->session)->hostname);
	printf("Kernel:       %s\n", perf_session__env(dr->session)->os_release);
	printf("Architecture: %s\n", perf_session__env(dr->session)->arch);
	printf("\n");

	printf("Processing events...\n");

	err = perf_session__process_events(dr->session);
	if (err) {
		pr_err("Failed to process events: %d\n", err);
		return err;
	}

	printf("Done processing events\n");

	print_statistics();

	if (verbose_mode)
		print_hist_entries(dr->session);

	return 0;
}

int cmd_data_reader(int argc, const char **argv)
{
	struct data_reader dr = {};
	struct perf_data data = {
		.mode = PERF_DATA_MODE_READ,
	};
	const struct option options[] = {
		OPT_STRING('i', "input", &input_name, "file",
			   "input file name (default: perf.data)"),
		OPT_BOOLEAN('v', "verbose", &verbose_mode,
			    "be verbose (show all samples)"),
		OPT_BOOLEAN('a', "all", &show_all_samples,
			    "show all samples (including those without symbols)"),
		OPT_END()
	};
	const char * const data_reader_usage[] = {
		"perf data-reader [<options>]",
		NULL
	};
	int err;

	err = hists__init();
	if (err < 0) {
		pr_err("Failed to init histogram subsystem\n");
		return err;
	}

	argc = parse_options(argc, argv, options, data_reader_usage, 0);

	data.path = input_name;

	symbol_conf.use_modules = true;
	symbol_conf.try_vmlinux_path = true;

	perf_tool__init(&dr.tool, /*ordered_events=*/false);
	dr.tool.sample		= process_sample_event;
	dr.tool.mmap		= process_mmap_event;
	dr.tool.mmap2		= process_mmap2_event;
	dr.tool.comm		= process_comm_event;
	dr.tool.exit		= process_exit_event;
	dr.tool.fork		= process_fork_event;
	dr.tool.namespaces	= perf_event__process_namespaces;
	dr.tool.attr		= perf_event__process_attr;
	dr.tool.build_id	= perf_event__process_build_id;
	dr.tool.id_index	= perf_event__process_id_index;
	dr.tool.auxtrace_info	= perf_event__process_auxtrace_info;
	dr.tool.auxtrace	= perf_event__process_auxtrace;
	dr.tool.ordering_requires_timestamps = true;

	dr.session = perf_session__new(&data, &dr.tool);
	if (IS_ERR(dr.session)) {
		pr_err("Failed to create session: %s\n",
		       strerror(-PTR_ERR(dr.session)));
		return PTR_ERR(dr.session);
	}

	err = symbol__annotation_init();
	if (err < 0)
		goto out_delete;

	err = symbol__init(perf_session__env(dr.session));
	if (err < 0)
		goto out_delete;

	sort_order = "dso,symbol";

	if (setup_sorting(NULL, perf_session__env(dr.session)) < 0) {
		pr_err("Failed to setup sorting\n");
		err = -1;
		goto out_delete;
	}

	err = __cmd_data_reader(&dr);

out_delete:
	perf_session__delete(dr.session);

	return err;
}
