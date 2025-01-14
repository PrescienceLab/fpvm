import pandas as pd
import os
import pathlib
from pathlib import Path
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

import numpy as np
import re
import math
import glob


def parse_hardware_times(csv_path):
    df = pd.read_csv(csv_path)
    hw_k = df["hw_to_kernel"].mean()
    k_user = df["kernel_to_user"].mean()
    return hw_k, k_user


signal_hw_k, signal_k_user = parse_hardware_times(
    "./kernel/signal-latency/signal_times.csv"
)
kmod_hw_k, kmod_k_user = parse_hardware_times("./kernel/signal-latency/kmod_times.csv")


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
            df = pd.read_csv(self.path / f"{self.benchmark}.fpvm_magic_0.amortcount.txt", sep="\t")
            self.imbue_df(df)
            return df
        except:
            return None

    def read_telemetry(self):
        call_wrap_time = 0
        hw_to_kernel_time = signal_hw_k
        kernel_to_user_time = signal_k_user

        if "trap_short_circuiting" in self.config:
            hw_to_kernel_time = kmod_hw_k
            kernel_to_user_time = kmod_k_user

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
                amor["decache"] = div_clamp(perf["decode_cache"]["sum"], numinst)
                amor["decode"] = div_clamp(perf["decoder"]["sum"], numinst)
                amor["bind"] = div_clamp(perf["bind"]["sum"], numinst)
                amor["emul"] = div_clamp(perf["emulate"]["sum"], numinst)
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
                    + amor["gc"]
                    + amor["fcall"]
                    + amor["corr"]
                )

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

for benchmark_entry in Path("sweep-results").iterdir():
    if not benchmark_entry.is_dir():
        continue
    benchmark = benchmark_entry.name
    for alt_entry in benchmark_entry.iterdir():
        alt = alt_entry.name
        for telem_entry in alt_entry.iterdir():
            telem = telem_entry.name
            for config_entry in telem_entry.iterdir():
                config = config_entry.name
                results.append(
                    BenchmarkResult(benchmark, alt, telem, config, config_entry)
                )


rusages = pd.concat([result.read_rusages() for result in results])

rusages.to_csv("sweep-results/rusage.csv", index=False)


def plot_overhead(ru_name):
    ru = rusages[rusages["alt"] == "boxed"]
    ru = ru[ru["telem"] == "basic_timing"]
    r = (
        ru.groupby(by=["config", "telem", "alt", "benchmark", "type"])
        .mean()
        .reset_index()
    )
    oh = r.pivot(index=["benchmark", "config"], columns="type", values=ru_name)
    oh["overhead"] = (oh["fpvm"] - oh["baseline"]) / oh["baseline"]
    oh.reset_index(inplace=True)
    oh.to_csv(f"sweep-results/{ru_name}_overhead.csv", index=False)
    plt.figure(figsize=(12, 8))  # Width of 12 and height of 8
    g = sns.barplot(data=oh, x="benchmark", hue="config", y="overhead")
    plt.legend(loc="lower left")

    g.set(title=f"{ru_name} overhead")
    plt.savefig(f"sweep-results/{ru_name}_overhead.pdf", format="pdf")


# plot_overhead('time')
# plot_overhead('stime')
# plot_overhead('utime')
# plot_overhead('maxrss')
# plot_overhead('minor')


# Instruction rank trace plots (figure 9 B and C from the paper as of Jan 2, 2025)


def load_ranks(f=lambda x: x):
    ranks = []
    for result in results:
        if (
            result.config == "instr_seq_emulation"
            and result.alt == "boxed"
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
fig, axs = plt.subplots(len(benchmark_names), 1, figsize=(5, 2 * len(benchmark_names)))

for i, bm in enumerate(benchmark_names):
    b = s[s["benchmark"] == bm]
    # axs[i].step(b['length'], b['perc'], where="mid", label=bm)
    sns.barplot(data=b, x="length", y="perc", ax=axs[i], color="black")
    axs[i].set_title(f"Histogram of Sequence Length - {bm}")
    axs[i].set_ylabel("Percentage")
    axs[i].set_xlabel(None)
    if i == len(benchmark_names) - 1:
        axs[i].set_xlabel("Sequence Length")
plt.tight_layout()
plt.savefig(f"sweep-results/8_A.pdf", format="pdf")


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

    plt.step(b["rank_r"], b["cum_perc_len"], where="mid", label=bm)
ax.set_title("Sequence Length Weighed Rank Popularity")
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
plt.legend()
plt.tight_layout()
plt.savefig(f"sweep-results/9_C.pdf", format="pdf")


# exit()




def plot_grouped_stacked_bar(fig_data, benchmark_column, hue, bar_parts, axis_name, output_name, configs):

    benchmark_names = fig_data[benchmark_column].unique()
    benchmark_count = len(benchmark_names)
    bar_count = len(configs)
    print(benchmark_count, bar_count)
    bar_axis_ticks = np.arange(benchmark_count)

    group_width = 0.9
    bar_width = group_width / bar_count
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.spines['right'].set_visible(False)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)


    ax.set_yticks(bar_axis_ticks)
    ax.set_yticklabels(benchmark_names)

    print(fig_data)

    for i, (name, config) in enumerate(configs):
        t = fig_data[fig_data[hue] == name]
        print(t)
        ticks = bar_axis_ticks - (group_width / 2) + (i * bar_width) + (bar_width / 2)
        print(name, ticks)
        for tick, benchmark in zip(ticks, benchmark_names):
            df = t[t[benchmark_column] == benchmark]
            if df.empty:
                continue
            bottom = 0
            for col, hatch, color, label in bar_parts:
                pt = df[col].mean()

                ax.barh(tick, pt, label=label, height=bar_width, left=bottom, color=color, edgecolor='black', linewidth=0.8)
                bottom += pt
            ax.text(bottom, tick, ' ' + name, horizontalalignment='left', verticalalignment='center', color='black', fontsize=8)

    # Create the legend
    handles = [mpatches.Patch(color=color, hatch=hatch, label=label) for _, hatch, color, label in bar_parts]
    ax.legend(handles=handles, loc='upper center', bbox_to_anchor=(0.4, 1.15), ncol=4, frameon=False)

    # rename the benchmark names on the ticks
    def format_tick(tick):
        rename_table = {
            'lorenz_attractor': 'Lorenz',
            'three_body_simulation': 'Three-body',
            'double_pendulum': 'Double-Pendulum'
        }
        if tick in rename_table:
            return rename_table[tick]
        return tick
    ax.set_yticklabels(map(format_tick, (item.get_text() for item in ax.get_yticklabels())))
    ax.set_ylabel("Benchmark")
    ax.set_xlabel(axis_name)
    plt.tight_layout()
    plt.savefig(output_name, format="pdf")



########################################################################################################
# Amortized Cost
########################################################################################################
telemetry = []

for result in results:
    t = result.read_telemetry()
    if t is None:
        continue
    telemetry.append(t)

telemetry = pd.concat(telemetry)
telemetry.to_csv(f"sweep-results/telemetry.csv", index=False)
telemetry = telemetry[telemetry["alt"] == "boxed"]

tel_configs = [
    # The order here is reversed for reasons
    ("SEQ KERN", "instr_seq_emulation trap_short_circuiting magic_correctness_trap"),
    ("KERN", "trap_short_circuiting magic_correctness_trap"),
    ("SEQ", "instr_seq_emulation magic_correctness_trap"),
    ("NONE", "no_accel"),
]

fig_data = []
for name, config in tel_configs:
    tel = telemetry[telemetry["config"] == config]
    tel.to_csv(f"sweep-results/telemetry_{name}.csv", index=False)

    tel = tel.drop(["benchmark", "alt", "config", "telem"], axis=1)
    t = tel.groupby(by="name", as_index=True, group_keys=False).mean()
    t['config'] = name
    fig_data.append(t)
fig_data = pd.concat(fig_data)
fig_data.reset_index(inplace=True)

bar_parts = [
    ('hw',      '//',   '#72C2A6',  'Hardware'),
    ('kern',    '//',   '#F68E67',  'Kernel'),
    ('decache', '//',   '#8FA0CA',  'Decoder Cache'),
    ('decode',  '//',   '#ABD85E',  'Decoder'),
    ('bind',    '//',   '#FDD945',  'Instruction Binding'),
    ('emul',    '//',   '#E3C497',  'Emulation'),
    ('gc',      '//',   '#B3B3B3',  'Garbage Collection'),
    ('fcall',   None,   '#ff5e7c',  'Foreign Calls'),
    ('corr',    '//',    '#2E77B2',  'Correctness Handler'),
]

plot_grouped_stacked_bar(fig_data,
                         benchmark_column='name',
                         hue='config',
                         bar_parts=bar_parts,
                         axis_name='Amortized CPU Cycles',
                         output_name='sweep-results/amort_costs.pdf',
                         configs=tel_configs)





########################################################################################################
# Amortized Count
########################################################################################################
amortcount = []

for result in results:
    t = result.read_amortcount()
    if t is None:
        continue
    amortcount.append(t)

amortcount = pd.concat(amortcount)
amortcount.to_csv(f"sweep-results/amortcount.csv", index=False)
amortcount = amortcount[amortcount["alt"] == "boxed"]
print(amortcount)


bar_configs = [
    # The order here is reversed for reasons
    ("SEQ KERN", "instr_seq_emulation trap_short_circuiting magic_correctness_trap"),
    ("KERN", "trap_short_circuiting magic_correctness_trap"),
    ("SEQ", "instr_seq_emulation magic_correctness_trap"),
    ("NONE", "no_accel"),
]

fig_data = []
for name, config in bar_configs:
    tel = amortcount[amortcount["config"] == config]
    tel.to_csv(f"sweep-results/amortcount_{name}.csv", index=False)

    tel = tel.drop(["factors", "alt", "config", "telem"], axis=1)
    t = tel.groupby(by="benchmark", as_index=True, group_keys=False).mean()
    t['config'] = name
    fig_data.append(t)
fig_data = pd.concat(fig_data)
fig_data.reset_index(inplace=True)

bar_parts = [
    ('fptraps',                '//',   '#72C2A6',  'Floating Point Traps'),
    ('promotions',             '//',   '#F68E67',  'Promotions'),
    ('clobbers',               '//',   '#8FA0CA',  'Clobbers'),
    ('demotions',              '//',   '#ABD85E',  'Demotions'),
    ('correctnesstraps',       '//',   '#FDD945',  'Correctness Traps'),
    ('correctnessdemotions',   '//',   '#B3B3B3',  'Correctness Demotions'),
    ('foreigncalls',           '//',   '#ff5e7c',  'Foreign Calls'),
]

plot_grouped_stacked_bar(fig_data,
                         benchmark_column='benchmark',
                         hue='config',
                         bar_parts=bar_parts,
                         axis_name='Amortized Count Per Fault',
                         output_name='sweep-results/amort_counts.pdf',
                         configs=bar_configs)















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
