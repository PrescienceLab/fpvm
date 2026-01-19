#! /usr/bin/python3

import os
import seaborn as sns
import pandas as pd
import glob
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from cycler import cycler
import numpy as np

num_colors = 14  # Number of colors in the cycle
cmap = plt.cm.nipy_spectral # Choose your colormap
colors = list(cmap(np.linspace(0.0, 0.99, num_colors)))
first_half = colors[int(len(colors)/2):]
second_half = colors[:-int(len(colors)/2)]
colors = reversed([val for pair in zip(first_half, reversed(second_half)) for val in pair])
plt.rcParams['axes.prop_cycle'] = cycler(color=colors)

def unify_benchmark_names(df, col):
    df[col] = df[col].replace('double_pendulum', 'Double Pend.')
    df[col] = df[col].replace('lorenz_attractor', 'Lorenz')
    df[col] = df[col].replace('three_body_simulation', 'Three Body')
    df[col] = df[col].replace('enzo', 'Enzo')
    df[col] = df[col].replace('enzo.exe', 'Enzo')
    df[col] = df[col].replace('bt', 'NAS BT')
    df[col] = df[col].replace('sp', 'NAS SP')
    df[col] = df[col].replace('is', 'NAS IS')
    df[col] = df[col].replace('ft', 'NAS FT')
    df[col] = df[col].replace('cg', 'NAS CG')
    df[col] = df[col].replace('fbench', 'FBench')
    df[col] = df[col].replace('ffbench', 'FFBench')
    df = df[df[col] != 'mg'] # Filter out mg and lu (they're unreliable even on the largest size)
    df = df[df[col] != 'lu']
    return df


def create_perf_df(output_path):
    csv_files = glob.glob(f"{output_path}/**/fpvm_magic_0_perf.csv", recursive=True)
    benchmark_dfs = []
    summary_df = None
    for csv_file in csv_files:
        with open(csv_file) as file:
            if len(str(file.read()).strip()) == 0:
                continue
        df = pd.read_csv(csv_file)
        df = df.rename(columns={'name':'factor'})
        benchmark_name = csv_file[(len(output_path)+1):][:-len("/fpvm_magic_0_perf.csv")]
        df['name'] = benchmark_name
        benchmark_dfs.append(df)

    for df in benchmark_dfs:
        if summary_df is None:
            summary_df = df.copy()
        else:
            summary_df = pd.concat([summary_df,df], axis=0)

    summary_df.columns = summary_df.columns.str.strip()
    summary_df = unify_benchmark_names(summary_df,'name')
    return summary_df

def create_telem_df(output_path):
    csv_files = glob.glob(f"{output_path}/**/fpvm_magic_0_telem.csv", recursive=True)
    benchmark_dfs = []
    telem_df = None
    for csv_file in csv_files:
        with open(csv_file) as file:
            if len(str(file.read()).strip()) == 0:
                continue
        df = pd.read_csv(csv_file)
        benchmark_name = csv_file[(len(output_path)+1):][:-len("/fpvm_magic_0_telem.csv")]
        df['name'] = benchmark_name
        benchmark_dfs.append(df)

    for df in benchmark_dfs:
        if telem_df is None:
            telem_df = df.copy()
        else:
            telem_df = pd.concat([telem_df,df], axis=0)

    telem_df.columns = telem_df.columns.str.strip()
    telem_df = unify_benchmark_names(telem_df,'name')
    return telem_df

def create_amort_df(output_path):
    csv_files = glob.glob(f"{output_path}/**/fpvm_magic_amortized.csv", recursive=True)
    df = None
    for csv_file in csv_files:
        with open(csv_file) as file:
            if len(str(file.read()).strip()) == 0:
                continue
        cur_df = pd.read_csv(csv_file)
        if df is None:
            df = cur_df
        else:
            df = pd.concat([df,cur_df], axis=0)
    df.columns = df.columns.str.strip()
    df.set_index('name')
    df = unify_benchmark_names(df,'name')
    return df

def create_timing_df(output_path):
    csv_files = glob.glob(f"{output_path}/**/*.fpvm_magic_0.timing.txt", recursive=True)
    df = None
    for csv_file in csv_files:
        with open(csv_file) as file:
            if len(str(file.read()).strip()) == 0:
                continue
        cur_df = pd.read_csv(csv_file, sep='\t')
        if df is None:
            df = cur_df
        else:
            df = pd.concat([df,cur_df], axis=0)
    df.columns = df.columns.str.strip()
    df.set_index('benchmark')
    df['fpvm_sys_user_sum'] = df['fpvm_sys'] + df['fpvm_user']
    df['fpvm_sys_prop'] = df['fpvm_sys'] / df['fpvm_sys_user_sum']
    df['fpvm_user_prop'] = df['fpvm_user'] / df['fpvm_sys_user_sum']
    df = unify_benchmark_names(df,'benchmark')
    return df


def plot_amort(output_path, amort_df): 
    plt.figure(figsize=(6.4 * 2.1, 4.8 * 0.8))
    ax = plt.subplot()
    nb_colors = len(plt.rcParams['axes.prop_cycle'])
    amort_df.plot.barh(
            x='name',
            y=['hw', 'kern', 'decache', 'decode', 'bind', 'emul', 'fcall', 'corr', 'set_ts', 'clear_ts', 'mark_in_signal', 'single_step_hw', 'single_step_kern'],
            title='Amortized Cost of an Emulated Instruction',
            stacked=True,
            ax=ax,
            )
    plt.ylabel('')
    plt.xlabel('Cycles')
    #handles, labels = ax.get_legend_handles_labels()
    #ax.legend(reversed(handles), reversed(labels), loc='center left', bbox_to_anchor=(1, 0.5))
    plt.tight_layout()
    plt.savefig(f'{output_path}/amort.pdf', format='pdf')

def plot_slowdown(output_path, timing_df):
    plt.figure()
    plt.figure(figsize=(6.4, 3.2))
    ax = plt.subplot()
    timing_df.plot.bar(
            x='benchmark',
            y=['slowdown_sum'],
            title='Benchmark Slowdown',
            xlabel='',
            ylabel='Slowdown',
            ax=ax,
            legend=False,
            )
    plt.tight_layout()
    plt.savefig(f'{output_path}/slowdown.pdf', format='pdf')

def plot_sys_vs_user(output_path, timing_df):
    plt.figure()
    plt.figure(figsize=(6.4, 3.2))
    ax = plt.subplot()
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: '{:.0%}'.format(y)))
    timing_df.plot.bar(
            x='benchmark',
            y=['fpvm_sys_prop', 'fpvm_user_prop'],
            stacked=True,
            title='Benchmark Percentage of Time (System vs. User)',
            xlabel='',
            ylabel='% of Time',
            ax=ax,
            )
    ax.legend(labels=['user', 'kernel'])
    plt.tight_layout()
    plt.savefig(f'{output_path}/sys_vs_user.pdf', format='pdf')

def analyse(output_path):
    perf_df = create_perf_df(output_path)
    print(perf_df.head())
    telem_df = create_telem_df(output_path)
    print(telem_df.head())

    perf_df = perf_df.merge(telem_df, on='name')

    perf_df['amort_count'] = perf_df['count'] / perf_df['useful_instructions_emulated']

    amort_df = create_amort_df(output_path)
    print(amort_df.head())
    timing_df = create_timing_df(output_path)
    print(timing_df.head())
    plot_amort(output_path, amort_df)
    plot_slowdown(output_path, timing_df)
    plot_sys_vs_user(output_path, timing_df)

analyse('results/latest')

