import json
import os
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np


def generate_plots(benchmark_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    traj_dir = os.path.join(output_dir, "trajectories")
    if not os.path.exists(traj_dir):
        os.makedirs(traj_dir)

    model_stats = defaultdict(
        lambda: {"success_count": 0, "total_count": 0, "total_score": 0.0}
    )
    task_steps = defaultdict(list)

    for filename in os.listdir(benchmark_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(benchmark_dir, filename)
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)

                    runs_to_process = []
                    if "run_details" in data:
                        for idx, r in enumerate(data["run_details"]):
                            safe_task = r.get("task", f"task_{idx}")
                            runs_to_process.append(
                                (r, filename.replace(".json", f"_{safe_task}.png"))
                            )
                    else:
                        runs_to_process.append(
                            (data, filename.replace(".json", ".png"))
                        )

                    for run_data, traj_filename in runs_to_process:
                        model = run_data.get("model", "Unknown")
                        task = run_data.get("task", "Unknown")
                        summary = run_data.get("summary", {})
                        success = summary.get("success", False)
                        score = summary.get("final_score", 0.0)
                        steps_taken = summary.get("steps_taken", 0)

                        model_stats[model]["total_count"] += 1
                        if success:
                            model_stats[model]["success_count"] += 1
                            task_steps[task].append(steps_taken)
                        model_stats[model]["total_score"] += score

                        # Trajectory plot
                        steps_data = run_data.get("steps", [])
                        if steps_data:
                            step_nums = []
                            rewards = []
                            violations = []

                            cumulative_reward = 0.0
                            for s in steps_data:
                                step_nums.append(s.get("step", 0))
                                r = s.get("reward")
                                if r is not None:
                                    cumulative_reward += r
                                rewards.append(cumulative_reward)
                                if s.get("blocked") or s.get("security_violation"):
                                    violations.append(s.get("step", 0))

                            plt.figure(figsize=(10, 4))
                            plt.plot(
                                step_nums,
                                rewards,
                                marker="o",
                                linestyle="-",
                                color="dodgerblue",
                                label="Reward",
                            )

                            for v in violations:
                                plt.axvline(
                                    x=v,
                                    color="red",
                                    linestyle="--",
                                    alpha=0.7,
                                    label=(
                                        "Security Violation"
                                        if v == violations[0]
                                        else ""
                                    ),
                                )

                            plt.title(f"Reward Trajectory: {task} ({model})")
                            plt.xlabel("Steps")
                            plt.ylabel("Reward")
                            plt.grid(True, alpha=0.3)

                            handles, labels = plt.gca().get_legend_handles_labels()
                            by_label = dict(zip(labels, handles, strict=False))
                            if by_label:
                                plt.legend(by_label.values(), by_label.keys())

                            plt.tight_layout()
                            plt.savefig(os.path.join(traj_dir, traj_filename))
                            plt.close()

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    # Plot 3: Average steps required to complete each task
    tasks = []
    avg_steps = []
    for task, steps_list in task_steps.items():
        tasks.append(task)
        avg_steps.append(np.mean(steps_list) if steps_list else 0)

    if tasks:
        # Sort tasks alphabetically
        sorted_indices = np.argsort(tasks)
        tasks = np.array(tasks)[sorted_indices]
        avg_steps = np.array(avg_steps)[sorted_indices]

        plt.figure(figsize=(10, 6))
        x_pos = np.arange(len(tasks))
        bars = plt.bar(x_pos, avg_steps, align="center", color="coral")
        plt.xticks(x_pos, tasks, rotation=45)
        plt.ylabel("Average Steps to Success")
        plt.title("Agentrology Benchmark: Average Steps to Success per Task")
        for bar in bars:
            height = bar.get_height()
            plt.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{height:.1f}",
                ha="center",
                va="bottom",
            )
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "average_steps_per_task.png"))
        plt.close()

    # Original Plot 1 & 2 logic reused here
    models = []
    success_rates = []
    avg_scores = []

    for model, stats in model_stats.items():
        models.append(model)
        total = stats["total_count"]
        success_rates.append((stats["success_count"] / total) * 100 if total > 0 else 0)
        avg_scores.append(stats["total_score"] / total if total > 0 else 0)

    models = np.array(models)
    success_rates = np.array(success_rates)
    avg_scores = np.array(avg_scores)

    if len(models) > 0:
        sort_idx = np.argsort(success_rates)[::1]
        models_sorted_sr = models[sort_idx]
        success_rates_sorted = success_rates[sort_idx]
    else:
        models_sorted_sr = models
        success_rates_sorted = success_rates

    plt.figure(figsize=(10, 6))
    y_pos = np.arange(len(models_sorted_sr))
    bars = plt.barh(y_pos, success_rates_sorted, align="center", color="skyblue")
    plt.yticks(y_pos, models_sorted_sr)
    plt.xlabel("Success Rate (%)")
    plt.title("Agentrology Benchmark: Success Rate by Model")
    for bar in bars:
        width = bar.get_width()
        plt.text(
            width + 1,
            bar.get_y() + bar.get_height() / 2.0,
            f"{width:.1f}%",
            va="center",
        )
    plt.xlim(0, max(success_rates, default=0) + 15)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "success_rate_by_model.png"))
    plt.close()

    if len(models) > 0:
        sort_idx_score = np.argsort(avg_scores)[::1]
        models_sorted_score = models[sort_idx_score]
        avg_scores_sorted = avg_scores[sort_idx_score]
    else:
        models_sorted_score = models
        avg_scores_sorted = avg_scores

    plt.figure(figsize=(10, 6))
    bars = plt.barh(y_pos, avg_scores_sorted, align="center", color="lightgreen")
    plt.yticks(y_pos, models_sorted_score)
    plt.xlabel("Average Final Score")
    plt.title("Agentrology Benchmark: Average Final Score by Model")
    for bar in bars:
        width = bar.get_width()
        plt.text(
            width + 0.01,
            bar.get_y() + bar.get_height() / 2.0,
            f"{width:.2f}",
            va="center",
        )
    plt.xlim(0, max(max(avg_scores, default=0) + 0.1, 1.0))
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "average_score_by_model.png"))
    plt.close()

    print(f"Plots successfully generated in {output_dir}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate benchmark plots.")
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default="benchmarks",
        help="Directory containing benchmak JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="assets",
        help="Directory to save the generated plots.",
    )
    args = parser.parse_args()

    generate_plots(args.benchmark_dir, args.output_dir)
