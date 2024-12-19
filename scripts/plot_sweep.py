import pandas as pd
import os
import pathlib
from pathlib import Path
import seaborn as sns
import matplotlib as plt

def add_column(df, name, value):
    df[name] = value
    return df


class BenchmarkResult:
    def __init__(self, benchmark, alt, telem, config, path):
        self.benchmark = benchmark
        self.alt = alt
        self.telem = telem
        self.config = config.replace('-', ' ')
        self.path = path

    def imbue_df(self, df):
        df['benchmark'] = self.benchmark
        df['alt'] = self.telem
        df['telem'] = self.telem
        df['config'] = self.config

    def read_rusages(self):
        df = pd.concat([
            add_column(pd.read_csv(self.path/'fpvm_magic_rusage.csv'), 'type', 'fpvm'),
            add_column(pd.read_csv(self.path/'baseline_rusage.csv'), 'type', 'baseline'),
        ])
        self.imbue_df(df)
        return df


results = []

for benchmark_entry in Path('sweep-results').iterdir():
    if not benchmark_entry.is_dir():
        continue
    benchmark = benchmark_entry.name
    for alt_entry in benchmark_entry.iterdir():
        alt = alt_entry.name
        for telem_entry in alt_entry.iterdir():
            telem = telem_entry.name
            for config_entry in telem_entry.iterdir():
                config = config_entry.name
                results.append(BenchmarkResult(benchmark, alt, telem, config, config_entry))




rusages = pd.concat([result.read_rusages() for result in results])
rusages.to_csv('sweep-results/rusage.csv', index=False)
print(rusages)

# First, gather all the rusage CSVs into sweep-results/rusage.csv
