import seaborn as sns
import pandas as pd
import glob
import matplotlib.pyplot as plt



# This function plots the length distribution using the results found in output_path.
# it outputs the result of this plotting into `output_path`/trace_length_dist.pdf as a seaborn histogram
def plot_trace_length_dist(output_path):


    log_files = glob.glob(f"{output_path}/**/magic*.fpvm_log", recursive=True)
    parsed_data = []
    for log in log_files:
        with open(log, 'r') as file:
            benchmark = log.split('/')[2]
            for line in file:
                if "TRACE BEGIN" in line:
                    # Split the line based on spaces
                    data = line.replace('(', ' ').replace(')',' ').split()
                    # Find the indices of instr_count and trace_count keywords
                    instr_index = data.index("instr_count") + 1
                    trace_index = data.index("trace_count") + 1
                    # Try converting values to integers, handle exceptions
                    try:
                        instr_count = int(data[instr_index])
                        trace_count = int(data[trace_index])
                        parsed_data.append((benchmark, instr_count, trace_count))
                    except (ValueError, IndexError):
                        print(data)
                        # Log or handle potential errors during conversion
                        pass

    # df = pd.DataFrame(parsed_data, columns=['benchmark', 'length', 'count'])
    # sns.scatterplot(df, x='length', y='count', hue='benchmark')
    # plt.savefig(f'{output_path}/trace_length_dist.pdf', format='pdf')
    #
    # return



    csv_files = glob.glob(f"{output_path}/**/*.tracehist.txt", recursive=True)

    print(csv_files)
    df = pd.concat([pd.read_csv(file, sep='\t') for file in csv_files], ignore_index=True).sort_values(by='length')

    sns.lineplot(df, x='length', y='cumprob', hue='benchmark')
    # sns.histplot(df, x='length', y='count', hue='benchmark', cumulative=True)

    print(df)
    plt.savefig(f'{output_path}/trace_length_dist.pdf', format='pdf')  # Replace 'my_seaborn_plot.pdf' with your desired filename

    pass

plot_trace_length_dist('results/latest')
