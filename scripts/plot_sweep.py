import pandas as pd
import os
import pathlib
from pathlib import Path
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker
import matplotlib.colors as mcolors


import numpy as np
import re
import math
import glob
import argparse

parser = argparse.ArgumentParser()


# sns.set_theme()
custom_params = {"axes.spines.right": False, "axes.spines.top": False}
sns.set_theme(style="ticks", rc=custom_params)

parser.add_argument("alt_to_plot", help="echo the string you use here", default="boxed")
args = parser.parse_args()

alt_to_plot = args.alt_to_plot


bar_parts = [
    # old colors:
    ("hw", None, "#72C2A6", "hw"),
    ("kern", None, "#F68E67", "kernel"),
    ("decache", None, "#8FA0CA", "decache"),
    ("decode", None, "#ABD85E", "decode"),
    ("bind", None, "#FDD945", "bind"),
    ("emul", None, "#E3C497", "emul"),
    ("altmath", None, "#b959c2", "altmath"),
    ("gc", None, "#B3B3B3", "gc"),
    ("fcall", None, "#ff5e7c", "fcall"),
    ("corr", None, "#2E77B2", "corr"),
    ("ret", None, "#69d7ff", "ret"),
]


# cmap = sns.color_palette("tab20b", 11)
# cmap = sns.color_palette("tab20", as_cmap=True)

# hex_colors = [mcolors.to_hex(cmap(i)) for i in np.linspace(0, 1, 11)]
# for i, e in enumerate(bar_parts):
#     bar_parts[i] = (e[0], e[1], hex_colors[i], e[3])

benchmarks_of_interest = [
    "enzo.exe",
    "double_pendulum",
    "fbench",
    "ffbench",
    "lorenz_attractor",
    "three_body_simulation",
]


palette = sns.color_palette(palette=list(map(lambda x: x[2], bar_parts)))
# Set the palette
sns.set_palette(palette)


# rename the benchmark names on the ticks
def rename_benchmark(tick):
    rename_table = {
        "enzo.exe": "Enzo",
        "lorenz_attractor": "Lorenz",
        "three_body_simulation": "3-body",
        "double_pendulum": "Double\nPend.",
        "cg.W": "NAS CG",
    }
    if tick in rename_table:
        return rename_table[tick]
    return tick


def rename_config(c):
    if c == "no_accel":
        return "NONE"
    if c == "instr_seq_emulation":
        return "SEQ"
    if c == "trap_short_circuiting":
        return "SHORT"
    if c == "instr_seq_emulation trap_short_circuiting":
        return "SEQ SHORT"


def parse_hardware_times(csv_path):
    df = pd.read_csv(csv_path)
    df["return"] = df["total"] - (df["hw_to_kernel"] + df["kernel_to_user"])
    hw_k = df["hw_to_kernel"].mean()
    k_user = df["kernel_to_user"].mean()
    k_return = df["return"].mean()
    print(hw_k, k_user, k_return)
    return hw_k, k_user, k_return


signal_hw_k, signal_k_user, signal_k_return = parse_hardware_times(
    "./kernel/signal-latency/signal_times.csv"
)

kmod_hw_k, kmod_k_user, kmod_k_return = parse_hardware_times(
    "./kernel/signal-latency/kmod_times.csv"
)


def add_column(df, name, value):
    df[name] = value
    return df


def get_performance(file: Path):
    metrics = []
    with open(file) as f:
        for line in f:
            # Check if the line is even interesting
            m = re.match(r"^fpvm\s+info\(.*\):\s+perf:\s+(\S.*) :\s+(\S.*)$", line)
            if not m:
                continue
            line = re.sub(r"^fpvm\s+info\(.*\):\s+perf:", "", line).strip()
            bits = line.split(" : ")

            m = {}
            m["name"] = bits[0].replace(" ", "_").strip()

            for p in bits[1].split(" "):
                name, val = p.split("=")
                m[name] = float(val)

            # Copmute avg, stddev ourselves just in case
            if m["count"] == 0:
                m["avg"] = 0.0
                m["std"] = 0.0
                m["min"] = 0
                m["max"] = 0
            else:
                m["avg"] = m["sum"] / m["count"]
                m["std"] = math.sqrt(m["sum2"] / m["count"] - m["avg"] * m["avg"])
            metrics.append(m)
    return metrics


def parse_telemetry(file: Path):
    t = {}
    with open(file) as f:
        for line in f:
            # Check if the line is even interesting
            m = re.match(r"^fpvm\s+info\(.*\):\s+telemetry:\s+(\S.*)$", line)
            if not m:
                continue
            # Cut the front off
            line = re.sub(r"^fpvm\s+info\(.*\):\s+telemetry:", "", line)

            for p in line.split(","):
                p = p.strip()
                p = re.sub(r"\(.*\)", "", p)
                match = re.match(r"^\d+", p)
                val = int(match.group())
                remainder = p[len(match.group()) :].strip().replace(" ", "_")
                t[remainder] = val
    return t


def div_clamp(a, b):
    if b != 0:
        return a / b
    return 0


class BenchmarkResult:
    def __init__(self, benchmark, alt, telem, config, path):
        self.benchmark = benchmark
        self.alt = alt
        self.telem = telem
        self.config = config.replace("-", " ")
        self.path = path

    def imbue_df(self, df):
        df["benchmark"] = self.benchmark
        df["alt"] = self.alt
        df["telem"] = self.telem
        df["config"] = self.config

    def read_rusages(self):
        df = pd.concat(
            [
                add_column(
                    pd.read_csv(self.path / "fpvm_magic_rusage.csv"), "type", "fpvm"
                ),
                add_column(
                    pd.read_csv(self.path / "baseline_rusage.csv"), "type", "baseline"
                ),
            ]
        )
        self.imbue_df(df)
        return df

    def read_amortcount(self):
        try:
            df = pd.read_csv(
                self.path / f"{self.benchmark}.fpvm_magic_0.amortcount.txt", sep="\t"
            )
            self.imbue_df(df)
            return df
        except:
            return None

    def read_raw_perfs(self):
        ps = []
        for log in glob.glob(os.path.join(self.path, "fpvm_magic_*.fpvm_log")):
            p = get_performance(log)
            if len(p) == 0:
                continue
            p = pd.DataFrame(p)
            s = p["sum"].sum()
            p["frac"] = p["sum"] / s
            ps.append(p)
        if len(ps) == 0:
            return None
        df = pd.concat(ps)
        self.imbue_df(df)
        return df

    def read_telemetry(self):
        call_wrap_time = 1000
        hw_to_kernel_time = signal_hw_k
        kernel_to_user_time = signal_k_user
        return_time = signal_k_return

        if "trap_short_circuiting" in self.config:
            hw_to_kernel_time = kmod_hw_k
            kernel_to_user_time = kmod_k_user
            return_time = kmod_k_return

        try:
            amoritized = []
            # Iterate over matching files
            for log in glob.glob(os.path.join(self.path, "fpvm_magic_*.fpvm_log")):
                t = parse_telemetry(log)
                perf_metrics = get_performance(log)

                # Create a nicer version of the perf data for use here:
                perf = {}
                for metric in perf_metrics:
                    perf[metric["name"]] = metric
                amor = {}

                numfpe = t.get("fp_traps", 0)
                numcor = t.get("correctness_traps", 0)
                numfor = t.get("correctness_foreign_calls", 0)
                numinst = t.get("instructions_emulated", 0)

                amor["name"] = self.benchmark
                amor["hw"] = div_clamp(hw_to_kernel_time * numfpe, numinst)
                amor["kern"] = div_clamp(kernel_to_user_time * numfpe, numinst)
                amor["ret"] = div_clamp(return_time * numfpe, numinst)
                amor["decache"] = div_clamp(perf["decode_cache"]["sum"], numinst)
                amor["decode"] = div_clamp(perf["decoder"]["sum"], numinst)
                amor["bind"] = div_clamp(perf["bind"]["sum"], numinst)

                amor["altmath"] = div_clamp(perf["altmath"]["sum"], numinst)
                amor["emul"] = div_clamp(perf["emulate"]["sum"], numinst)
                amor["emul"] -= amor["altmath"]

                amor["gc"] = div_clamp(perf["garbage_collector"]["sum"], numinst)
                amor["fcall"] = div_clamp(
                    perf["foreign_call"]["sum"] + call_wrap_time * numfor, numinst
                )
                amor["corr"] = div_clamp(
                    perf["correctness"]["sum"]
                    + (hw_to_kernel_time + kernel_to_user_time) * numcor,
                    numinst,
                )
                amor["total"] = (
                    amor["hw"]
                    + amor["kern"]
                    + amor["decache"]
                    + amor["decode"]
                    + amor["bind"]
                    + amor["emul"]
                    + amor["altmath"]
                    + amor["gc"]
                    + amor["fcall"]
                    + amor["corr"]
                )

                amor["numinst"] = numinst

                amoritized.append(amor)
            df = pd.DataFrame(amoritized)
            self.imbue_df(df)
            return df
        except:
            return None
        # try:
        #     df = pd.read_csv(self.path / "fpvm_magic_amortized.csv")
        #     self.imbue_df(df)
        #     return df
        # except:
        #     return None

    # Return a dataframe containing the instruction ranks from instruction trace runs.
    def read_instruction_ranks(self):
        with open(self.path / "fpvm_magic_0.fpvm_log", "r") as file:
            matching_lines = [line.strip() for line in file if "trace: rank" in line]
        if len(matching_lines) == 0:
            return None

        data = {
            "rank_r": [],
            "count": [],
            "perc": [],
            "cum_perc": [],
            "length": [],
        }
        # find all decimals and floating point numbers in a string
        pattern = "[\d]+[.,\d]+|[\d]*[.][\d]+|[\d]+"
        for line in matching_lines:
            l = line.split("trace: rank")[1].strip()
            numbers = re.findall(pattern, l)
            data["rank_r"].append(int(numbers[0]))
            data["count"].append(int(numbers[1]))
            data["perc"].append(float(numbers[2]))
            data["cum_perc"].append(float(numbers[3]))
            data["length"].append(int(numbers[4]))

        if len(data["count"]) == 0:
            return None

        d = pd.DataFrame(data)
        d["perc_count"] = 100.0 * (d["count"] / sum(d["count"]))
        d["benchmark"] = self.benchmark
        return d


results = []

for benchmark in benchmarks_of_interest:
    # if the benchmark is in sweep-results
    if not Path(f"sweep-results/{benchmark}").exists():
        continue
    benchmark_entry = Path(f"sweep-results/{benchmark}")
    for alt_entry in benchmark_entry.iterdir():
        alt = alt_entry.name
        for telem_entry in alt_entry.iterdir():
            telem = telem_entry.name
            for config_entry in telem_entry.iterdir():
                config = config_entry.name
                results.append(
                    BenchmarkResult(benchmark, alt, telem, config, config_entry)
                )


rusages = []

for result in results:
    try:
        rusages.append(result.read_rusages())
    except:
        continue

rusages = pd.concat(rusages)
rusages.to_csv("sweep-results/rusage.csv", index=False)


def plot_slowdown(ru_name, title):
    ru = rusages[rusages["alt"] == alt_to_plot]
    ru = ru[ru["telem"] == "basic_timing"]
    r = (
        ru.groupby(by=["config", "telem", "alt", "benchmark", "type"])
        .mean()
        .reset_index()
    )

    oh = r.pivot(index=["benchmark", "config"], columns="type", values=ru_name)
    # oh["overhead"] = (oh["fpvm"] - oh["baseline"]) / oh["baseline"]
    oh["slowdown"] = oh["fpvm"] / oh["baseline"]
    oh.reset_index(inplace=True)
    oh.to_csv(f"sweep-results/{ru_name}_slowdown.csv", index=False)
    plt.figure(figsize=(6, 4))
    hue_order = ["NONE", "SEQ", "SHORT", "SEQ SHORT"]
    oh["config"] = oh["config"].apply(rename_config)
    # oh = oh.sort_values(by="slowdown", ascending=False)
    g = sns.barplot(
        data=oh,
        x="benchmark",
        y="slowdown",
        hue="config",
        hue_order=hue_order,
        edgecolor="black",
        linewidth=1.0,
    )
    plt.legend(fontsize=8)
    # plt.legend(loc="upper right", title="Technique")
    for c in g.containers:
        g.bar_label(c, fmt=" %.1fx", fontsize=7, rotation=90, fontweight="bold")

    g.set_xticklabels(
        map(rename_benchmark, (item.get_text() for item in g.get_xticklabels()))
    )

    g.set_xlabel("Benchmark")
    g.set_ylabel("Slowdown")

    g.set(title=title)
    plt.tight_layout()
    plt.savefig(
        f"sweep-results/{ru_name}_slowdown.pdf", format="pdf", bbox_inches="tight"
    )


plot_slowdown("time", "Application Slowdown")


# exit()
# plot_slowdown('stime')
# plot_slowdown('utime')
# plot_slowdown('maxrss')
# plot_slowdown('minor')


# Instruction rank trace plots (figure 9 B and C from the paper as of Jan 2, 2025)


def load_ranks(f=lambda x: x):
    ranks = []
    for result in results:
        if (
            result.config == "instr_seq_emulation"
            and result.alt == alt_to_plot
            and result.telem == "instruction_traces"
        ):
            r = result.read_instruction_ranks()
            if r is None:
                continue
            ranks.append(f(r))
    return pd.concat(ranks)


# Figure 8.A (histogram)


def group_thing(ranks):
    bm = ranks["benchmark"][0]
    s = ranks.groupby(["length"], as_index=False).sum()
    s["benchmark"] = bm
    return s


s = load_ranks(group_thing)

benchmark_names = s["benchmark"].unique()

fig, ax = plt.subplots(figsize=(5, 3))

for i, bm in enumerate(benchmark_names):
    b = s[s["benchmark"] == bm]
    b["cum_perc"] = b["perc"].cumsum()
    ax.step(data=b, x="length", y="cum_perc", label=bm)
    ax.set_xlabel(None)

ax.set_title(f"CDF of Instruction Sequence Length")
ax.set_ylabel("Percentage")
ax.set_xlabel("Sequence Length")
plt.legend()
# plt.xlim(0, 20)  # Set the x-axis limits to 0 and 10

# make the x axis log
# plt.xscale('log')
plt.tight_layout()
plt.savefig(
    f"sweep-results/sequence_length_distribution.pdf", format="pdf", bbox_inches="tight"
)


# Figure 8.BC
def cum_perc_count_transformer(ranks):
    s = ranks.sort_values(by="length")
    s["cum_perc_count"] = s["perc_count"].cumsum()
    return s


s = load_ranks(cum_perc_count_transformer)
fig, ax = plt.subplots(figsize=(5, 3))
for bm in s["benchmark"].unique():
    b = s[s["benchmark"] == bm]
    plt.step(b["length"], b["cum_perc_count"], where="mid", label=bm)

plt.legend()
ax.set_title("Cumulative Percentage of Count")
plt.xlabel("Sequence Length")
plt.ylabel("Percentage of Emulated Sequences")
plt.tight_layout()
plt.savefig(f"sweep-results/8_BC.pdf", format="pdf")


# Figure 9.B
fig, ax = plt.subplots(figsize=(5, 3))
s = load_ranks()
for bm in s["benchmark"].unique():
    b = s[s["benchmark"] == bm]
    b["perc_len"] = (b["perc"] / 100.0) * b["length"]
    b["cum_perc_len"] = b["perc_len"].cumsum()

    # b['cum_perc_len'] /= max(b['cum_perc_len'])
    # b['rank_r'] /= max(b['rank_r'])

    plt.step(b["rank_r"], b["cum_perc_len"], where="mid", label=bm)
# plt.plot([0, 1], [0, 1], 'k--')
ax.set_title("Sequence Length Weighed Rank Popularity")
plt.xlabel("Sequence Rank")
plt.ylabel("Weighted Sequence Length")
plt.legend()
plt.tight_layout()
plt.savefig(f"sweep-results/9_B.pdf", format="pdf")


# Figure 9.C
fig, ax = plt.subplots(figsize=(5, 3))
s = load_ranks()
for bm in s["benchmark"].unique():
    b = s[s["benchmark"] == bm]
    plt.step(b["rank_r"], b["cum_perc"], where="mid", label=bm)

# sns.lineplot(data=ranks, x='rank_r', y='cum_perc', hue='benchmark', ax=ax)
ax.set_title("Instruction Rank Popularity")
plt.ylabel("Percentage")
plt.xlabel("Sequence Rank")
plt.legend()
plt.tight_layout()
plt.savefig(f"sweep-results/instruction_rankpop.pdf", format="pdf")


# exit()


def plot_grouped_stacked_bar(
    fig_data,
    benchmark_column,
    hue,
    bar_parts,
    axis_name,
    output_name,
    configs,
    show_improvement=True,
    show_labels=True,
    figsize=(6, 6),
):

    benchmark_names = fig_data[benchmark_column].unique()
    benchmark_count = len(benchmark_names)
    bar_count = len(configs)
    print(benchmark_count, bar_count)
    bar_axis_ticks = np.arange(benchmark_count)

    group_width = 0.9
    bar_width = group_width / bar_count

    fig, axs = plt.subplots(1, 1, figsize=figsize)
    ax = axs
    ax.spines["right"].set_visible(False)
    # ax.xaxis.grid(True)
    ax.set_axisbelow(True)

    ax.set_yticks(bar_axis_ticks)
    ax.set_yticklabels(benchmark_names)

    if not "total" in fig_data:
        show_improvement = False
    if show_improvement:
        base = fig_data[fig_data[hue] == "NONE"]
        bases = {}
        for index, row in base.iterrows():
            bases[row[benchmark_column]] = row["total"]
        fig_data["total_frac"] = 1.0

        for index, row in fig_data.iterrows():
            b = bases[row[benchmark_column]]
            fig_data.at[index, "total_frac"] = row["total"] / b
    print(fig_data)

    for i, (name, config) in enumerate(configs):
        t = fig_data[fig_data[hue] == name]
        ticks = bar_axis_ticks - (group_width / 2) + (i * bar_width) + (bar_width / 2)
        for tick, benchmark in zip(ticks, benchmark_names):
            df = t[t[benchmark_column] == benchmark]
            if df.empty:
                continue
            bottom = 0
            for col, hatch, color, label in bar_parts:
                pt = df[col].mean()

                ax.barh(
                    tick,
                    pt,
                    label=label,
                    height=bar_width,
                    left=bottom,
                    color=color,
                    hatch=hatch,
                    edgecolor="black",
                    linewidth=0.5,
                    # linewidth=0.8,
                )
                bottom += pt
            if show_labels:
                label = " " + name
                if show_improvement and name != "NONE":
                    f = df["total_frac"].mean()
                    label += f" ({1/f:.1f}x)"
                ax.text(
                    bottom,
                    tick,
                    label,
                    horizontalalignment="left",
                    verticalalignment="center",
                    color="black",
                    fontsize=8,
                )

    # Create the legend
    handles = [
        mpatches.Patch(color=color, hatch=hatch, label=label)
        for _, hatch, color, label in bar_parts
    ]
    print("BAR PARTS:", len(bar_parts), math.ceil(len(bar_parts) / 2))
    plt.legend(
        handles=handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.15),
        ncol=math.ceil(len(bar_parts) / 2),
        fontsize=8,
    )
    ax.relim()
    ax.autoscale_view()  # Rescale the view to fit the new limits

    ax.set_yticklabels(
        map(rename_benchmark, (item.get_text() for item in ax.get_yticklabels()))
    )
    # ax.set_ylabel("Benchmark")
    ax.set_xlabel(axis_name)
    # plt.setp(ax.get_yticklabels(), rotation=90, ha='right', va='center')  # Adjust ha and va as needed
    plt.tight_layout()
    plt.savefig(output_name, format="pdf")


########################################################################################################
# Amortized Cost
########################################################################################################


def plot_amort_cost(tel_configs, output_path, figsize):

    telemetry = []

    for result in results:
        t = result.read_telemetry()
        if t is None:
            continue
        telemetry.append(t)

    show_improvement = False

    for n, _ in tel_configs:
        if n == "NONE":
            show_improvement = True

    telemetry = pd.concat(telemetry)
    telemetry.to_csv(f"sweep-results/telemetry.csv", index=False)
    telemetry = telemetry[telemetry["alt"] == alt_to_plot]

    fig_data = []
    for name, config in tel_configs:
        tel = telemetry[telemetry["config"] == config]
        tel.to_csv(f"sweep-results/telemetry_{name}.csv", index=False)

        tel = tel.drop(["benchmark", "alt", "config", "telem"], axis=1)
        t = tel.groupby(by="name", as_index=True, group_keys=False).mean()
        t["config"] = name
        fig_data.append(t)
    fig_data = pd.concat(fig_data)
    fig_data.reset_index(inplace=True)
    print("fig data")
    print(fig_data)

    # bar_parts = [
    #     # ('hw',      None,   '#ff5959',  'Hardware'), # red
    #     # ('kern',    None,   '#ffb459',  'Kernel'), # red
    #     # ('decache', None,   '#6aff59',  'Decoder Cache'),
    #     # ('decode',  None,   '#59ffcd',  'Decoder'),
    #     # ('bind',    None,   '#59e6ff',  'Instruction Binding'),
    #     # ('emul',    None,   '#59a1ff',  'Emulation Overhead'),
    #     # ('altmath', None,   '#8059ff',  'Alternative Math'),
    #     # ('gc',      None,   '#d1d1d1',  'Garbage Collection'),
    #     # ('fcall',   None,   '#4dff00',  'Foreign Calls'),
    #     # ('corr',    None,   '#ff0015',  'Correctness Handler'),
    #     # ('ret',     None,   '#fff959',  'Signal Return'), # red
    #     # old colors:
    #     ("hw", None, "#72C2A6", "hw"),
    #     ("kern", None, "#F68E67", "kern"),
    #     ("decache", None, "#8FA0CA", "decache"),
    #     ("decode", None, "#ABD85E", "decode"),
    #     ("bind", None, "#FDD945", "bind"),
    #     ("emul", None, "#E3C497", "emul"),
    #     ("altmath", None, "#b959c2", "altmath"),
    #     ("gc", None, "#B3B3B3", "gc"),
    #     ("fcall", None, "#ff5e7c", "fcall"),
    #     ("corr", None, "#2E77B2", "corr"),
    #     ("ret", None, "#69d7ff", "ret"),
    # ]

    plot_grouped_stacked_bar(
        fig_data,
        benchmark_column="name",
        hue="config",
        bar_parts=bar_parts,
        axis_name="Amortized CPU Cycles",
        output_name=output_path,
        show_labels=len(tel_configs) > 1,
        configs=tel_configs,
        show_improvement=show_improvement,
        figsize=figsize,
    )


plot_amort_cost(
    [
        ("SEQ SHORT", "instr_seq_emulation trap_short_circuiting"),
        ("SHORT", "trap_short_circuiting"),
        ("SEQ", "instr_seq_emulation"),
        ("NONE", "no_accel"),
    ],
    "sweep-results/amort_costs.pdf",
    figsize=(6, 5),
)

plot_amort_cost(
    [
        ("NONE", "no_accel"),
    ],
    "sweep-results/amort_costs_base.pdf",
    figsize=(6, 4.5),
)

plot_amort_cost(
    [
        ("SHORT", "trap_short_circuiting"),
        ("NONE", "no_accel"),
    ],
    "sweep-results/amort_costs_base_kmod.pdf",
    figsize=(6, 4.5),
)


plot_amort_cost(
    [
        ("SHORT", "trap_short_circuiting"),
    ],
    "sweep-results/amort_costs_kmod.pdf",
    figsize=(6, 4.5),
)

plot_amort_cost(
    [
        ("SEQ SHORT", "instr_seq_emulation trap_short_circuiting"),
        ("SHORT", "trap_short_circuiting"),
        ("SEQ", "instr_seq_emulation"),
    ],
    "sweep-results/amort_costs_all_accel.pdf",
    figsize=(6, 4.5),
)

########################################################################################################
# Amortized Count
########################################################################################################
# amortcount = []

# for result in results:
#     t = result.read_amortcount()
#     if t is None:
#         continue
#     amortcount.append(t)

# amortcount = pd.concat(amortcount)
# amortcount.to_csv(f"sweep-results/amortcount.csv", index=False)
# amortcount = amortcount[amortcount["alt"] == alt_to_plot]


# bar_configs = [
#     # The order here is reversed for reasons
#     ("SEQ SHORT", "instr_seq_emulation trap_short_circuiting"),
#     ("SHORT", "trap_short_circuiting"),
#     ("SEQ", "instr_seq_emulation"),
#     ("NONE", "no_accel"),
# ]

# fig_data = []
# for name, config in bar_configs:
#     tel = amortcount[amortcount["config"] == config]
#     tel.to_csv(f"sweep-results/amortcount_{name}.csv", index=False)

#     tel = tel.drop(["factors", "alt", "config", "telem"], axis=1)
#     t = tel.groupby(by="benchmark", as_index=True, group_keys=False).mean()
#     t["config"] = name
#     fig_data.append(t)
# fig_data = pd.concat(fig_data)
# fig_data.reset_index(inplace=True)

# bar_parts = [
#     ("fptraps", None, "#72C2A6", "Floating Point Traps"),
#     ("promotions", None, "#F68E67", "Promotions"),
#     ("clobbers", None, "#8FA0CA", "Clobbers"),
#     ("demotions", None, "#ABD85E", "Demotions"),
#     ("correctnesstraps", None, "#FDD945", "Correctness Traps"),
#     ("correctnessdemotions", None, "#B3B3B3", "Correctness Demotions"),
#     ("foreigncalls", None, "#ff5e7c", "Foreign Calls"),
# ]

# plot_grouped_stacked_bar(
#     fig_data,
#     benchmark_column="benchmark",
#     hue="config",
#     bar_parts=bar_parts,
#     axis_name="Amortized Count Per Fault",
#     output_name="sweep-results/amort_counts.pdf",
#     configs=bar_configs,
#     figsize=(6, 6),
# )


########################################################################################################

telemetry = pd.read_csv("sweep-results/telemetry.csv")
telemetry = telemetry[
    telemetry["config"] == "instr_seq_emulation trap_short_circuiting"
]
alt = pd.pivot(telemetry, values="numinst", index="name", columns="alt").reset_index()
alt["vanilla"] = 100 * (alt["vanilla"] / alt["boxed"])
alt["boxed"] = 100

fig, ax = plt.subplots(figsize=(5, 4))

ca = "black"
cb = "red"
ax.barh(alt["name"], alt["boxed"], linewidth=0.8, edgecolor="black", color=ca)
ax.barh(
    alt["name"],
    alt["vanilla"],
    label="Essential Instructions Emulated",
    linewidth=0.8,
    edgecolor="black",
    color=cb,
)
for index, row in alt.iterrows():
    v = row["vanilla"]
    name = row["name"]
    print(name, v)
    ha = "left"
    color = cb
    if v > 50:
        ha = "right"
        color = ca
    ax.text(
        v,
        name,
        f" {v:.2f}% ",
        horizontalalignment=ha,
        verticalalignment="center",
        color=color,
        fontsize=8,
    )

ax.set_ylabel("Benchmark")
ax.set_yticklabels(
    map(rename_benchmark, (item.get_text() for item in ax.get_yticklabels()))
)
plt.tight_layout()
plt.legend(loc="upper center", bbox_to_anchor=(0.5, 1.15), fontsize=6.5, frameon=False)
plt.savefig(f"sweep-results/perc_essential.pdf", format="pdf", bbox_inches="tight")

########################################################################################################


# fig, ax = plt.subplots(figsize=(8, 6))
# fig_data['perc_emul'] = 100.0 * (fig_data['emul'] / fig_data['total'])
# sns.barplot(data=fig_data, x='name', y='perc_emul', hue='config', ax=ax)
# ax.set_xlabel("Benchmark")
# ax.set_ylabel("Percentage of overhead spent emulating")
# plt.savefig(f"sweep-results/perc_emul.pdf", format="pdf")


# for name, config in tel_configs:
#     tel = telemetry[telemetry["config"] == config]
#     tel.to_csv(f"sweep-results/telemetry_{name}.csv", index=False)
#
#     tel = tel.drop(["benchmark", "alt", "config", "telem"], axis=1)
#     t = tel.groupby(by="name", as_index=True, group_keys=False).mean()
#     t.to_csv(f"sweep-results/group_{name}.csv", index=False)
#
#     value_vars = "hw,kern,decache,decode,bind,emul,gc,fcall".split(",")
#
#     print(config)
#     print(t)
#
#     fig, ax = plt.subplots(figsize=(8, 6))
#     x = np.arange(len(t.index))
#
#     # Accumulate the bottom for stacking
#     bottom = np.zeros(len(t.index))
#     for column in value_vars:
#         ax.barh(x, t[column], label=column, left=bottom)
#         bottom += t[column]
#
#     # Customize the chart
#     ax.set_yticks(x)
#     ax.set_yticklabels(t.index)
#     ax.legend()
#     ax.set_ylabel("Benchmark")
#     ax.set_xlabel("CPU Cycles")
#     ax.set_title("Overhead breakdown for " + name)
#     plt.tight_layout()
#
#     # plt.figure(figsize=(12, 8))
#     # ax = sns.histplot(t, x='benchmark', hue='variable', weights='value', multiple='stack')
#     plt.savefig(f"sweep-results/telem_{name}.pdf", format="pdf")


print()
print()
print()
print()
print("==========================================================================")
print()
print()
print()
print()


raw = []

for result in results:
    if result.telem != "telem_perf":
        continue
    if result.alt != alt_to_plot:
        continue
    t = result.read_raw_perfs()

    if t is None:
        continue
    raw.append(t)

raw_perfs = pd.concat(raw)
print("raw perfs:")
altmaths = raw_perfs[raw_perfs["name"] == "altmath"]
altmaths = altmaths[altmaths["alt"] == alt_to_plot]
altmaths["time_spent_in_alt"] = altmaths["sum"] / 2861429992
print(altmaths)
altmaths = altmaths.filter(["benchmark", "config", "time_spent_in_alt"])
altmaths.set_index(["benchmark", "config"], inplace=True)
print(altmaths)

rub = rusages[rusages["alt"] == alt_to_plot]
rub = rub[rub["telem"] == "basic_timing"]

oh = rub.pivot(index=["benchmark", "config"], columns="type", values="time")
oh = oh.join(altmaths)
oh["adjusted"] = oh["baseline"] + oh["time_spent_in_alt"]
# oh["adjusted"] = oh["baseline"] + (oh["frac"] * (oh["fpvm"] - oh["baseline"]))
# oh["overhead"] = (oh["adjusted"] - oh["baseline"]) / oh["baseline"]
# oh["overhead"] = (oh["fpvm"] - oh["adjusted"]) / oh["adjusted"]
oh["slowdown"] = (
    oh["fpvm"] / oh["adjusted"]
)  # (oh["fpvm"] - oh["adjusted"]) / oh["adjusted"]
print(oh)
oh.reset_index(inplace=True)

plt.figure(figsize=(6, 4))
hue_order = ["NONE", "SEQ", "SHORT", "SEQ SHORT"]
oh["config"] = oh["config"].apply(rename_config)
# oh = oh.sort_values(by="slowdown", ascending=False)
g = sns.barplot(
    data=oh,
    x="benchmark",
    y="slowdown",
    hue="config",
    hue_order=hue_order,
    edgecolor="black",
    linewidth=0.5,
)
plt.legend(fontsize=8)
plt.axhline(1, color="red", linestyle="-", label="Best Possible")
g.set_xticklabels(
    map(rename_benchmark, (item.get_text() for item in g.get_xticklabels()))
)


# set the ylimit to (0, 24)
g.set_ylim(0, 25)
g.yaxis.set_major_formatter(ticker.ScalarFormatter())
g.yaxis.get_major_formatter().set_scientific(False)  # Disable scientific notation

g.set_xlabel("Benchmark")
g.set_ylabel("Slowdown (1 is Best Possible)")
plt.title("Slowdown from lower bound")

for c in g.containers:
    g.bar_label(c, fmt=" %.2fx", fontsize=7, rotation=90, fontweight="bold")
plt.tight_layout()


plt.savefig(f"sweep-results/altmath_overhead.pdf", format="pdf", bbox_inches="tight")


for label, _, hex, _ in bar_parts:
    print(f"\\definecolor{{{label}Color}}{{HTML}}{{{hex[1:]}}}")
    print(f"\\newcommand{{\\{label}}}{{\\textcolor{{{label}Color}}{{\\bf {label}}}}}")
