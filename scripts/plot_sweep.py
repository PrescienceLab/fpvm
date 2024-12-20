import pandas as pd
import os
import pathlib
from pathlib import Path
import seaborn as sns
import matplotlib.pyplot as plt

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
        df['alt'] = self.alt
        df['telem'] = self.telem
        df['config'] = self.config

    def read_rusages(self):
        df = pd.concat([
            add_column(pd.read_csv(self.path/'fpvm_magic_rusage.csv'), 'type', 'fpvm'),
            add_column(pd.read_csv(self.path/'baseline_rusage.csv'), 'type', 'baseline'),
        ])
        self.imbue_df(df)
        return df

    def read_telemetry(self):

        try:
            df = pd.read_csv(self.path/'fpvm_magic_amortized.csv')
            self.imbue_df(df)
            return df
        except:
            return None


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

def plot_overhead(ru_name):
    ru = rusages[rusages['alt'] == 'boxed']
    ru = ru[ru['telem'] == 'basic_timing']
    r = ru.groupby(by=['config', 'telem', 'alt', 'benchmark', 'type']).mean().reset_index()
    print(r)
    oh = r.pivot(index=['benchmark', 'config'], columns='type', values=ru_name)
    print(oh)
    oh['overhead'] = (oh['fpvm'] - oh['baseline']) / oh['baseline']
    oh.reset_index(inplace=True)
    oh.to_csv(f'sweep-results/{ru_name}_overhead.csv', index=False)
    plt.figure(figsize=(12, 8))  # Width of 12 and height of 8
    g = sns.barplot(data=oh, x='benchmark', hue='config', y='overhead')
    plt.legend(loc='lower left')

    g.set(title=f'{ru_name} overhead')
    plt.savefig(f'sweep-results/{ru_name}_overhead.pdf', format='pdf')


plot_overhead('time')
plot_overhead('stime')
plot_overhead('utime')
# plot_overhead('maxrss')
# plot_overhead('minor')


telemetry = []

for result in results:
    t = result.read_telemetry()
    if t is None:
        continue
    telemetry.append(t)

print(telemetry)
tel = pd.concat(telemetry)
tel.to_csv('sweep-results/telemetry.csv', index=False)




t = pd.melt(tel, id_vars=['benchmark', 'config'], value_vars='hw,kern,decache,decode,bind,emul,gc,fcall'.split(','))

print(t)
plt.figure(figsize=(12, 8))  # Width of 12 and height of 8
ax = sns.histplot(t, x='benchmark', hue='variable', weights='value', multiple='stack')
plt.savefig('sweep-results/telem.pdf', format='pdf')
