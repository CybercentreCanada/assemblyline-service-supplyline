from argparse import ArgumentParser, Namespace
from pathlib import Path

import pythonnet

pythonnet.load("coreclr")

import clr

clr.AddReference("Microsoft.Build.Locator")

from Microsoft.Build.Locator import MSBuildLocator

# Setup MSBuild Dependency
if not MSBuildLocator.IsRegistered:
    instance = MSBuildLocator.RegisterDefaults()
    print(f"Registered MSBuild from: {instance.MSBuildPath}")


# MSBuildLocator must be registered before any MSBuild assemblies are loaded.
clr.AddReference("Microsoft.Build")

# These imports must come after MSBuild is loaded.
from Microsoft.Build.Construction import ProjectRootElement
from Microsoft.Build.Evaluation import Project, ProjectCollection


def generate_artifact(dump_path: str, contents: str) -> None:
    """Generates an artifact by writing the provided contents to the specified dump path."""
    print(f"Artifact produced: {contents}")

    with open(dump_path, "w") as f:
        f.write(contents)


def eval_exec(project: Project, task: clr.Object) -> str:
    """Evaluates an MSBuild Exec task, expanding any properties and environment variables."""
    raw_command = task.Parameters["Command"]

    expanded_command = project.ExpandString(raw_command)

    if task.Parameters.ContainsKey("EnvironmentVariables"):
        expanded_command = task.Parameters["EnvironmentVariables"] + " " + expanded_command

    return expanded_command


def process_targets(project: Project, dump_path: Path) -> None:
    """Processes the targets in the MSBuild project, extracting Exec tasks and generating artifacts."""
    exec_tasks = [
        task
        for target in project.Targets
        for task in target.Tasks
        if task.Name == "Exec"
    ]

    for idx, task in enumerate(exec_tasks):
        generate_artifact(dump_path / f"exec-{idx}.ps1", eval_exec(project, task))


def parse_args() -> Namespace:
    """Parses command-line arguments for the MSBuild Exec task collector."""
    parser = ArgumentParser(description="Collect Exec tasks from MSBuild projects")
    parser.add_argument("project_path", help="Path to the MSBuild project file (.csproj, .vbproj, etc.)")
    parser.add_argument("dump_path", help="Path to the dump file where collected Exec tasks will be stored", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # To mimimize vulnerability surface, we directly load the project into an empty project collection.
    root = ProjectRootElement.Open(args.project_path)

    collection = ProjectCollection()

    # This kicks off project evaluation, which is generally read-only.
    project = Project(root, None, None, collection)

    process_targets(project, args.dump_path)


if __name__ == "__main__":
    main()
