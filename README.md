[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_supplyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-supplyline)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-supplyline)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-supplyline)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-supplyline)](./LICENSE)
# Supplyline Service

This Assemblyline service identifies and extracts supply-chain embedded malicious payloads.

## Supplyline Environment Requirements
Supplyline works similar to all other AssemblyLine services, so the general compatability matrix is shared. However, Supplyline has some unique requirements as well:
  - Linux Kernel Version 6.12 or greater
  - Landlock must be enabled

If you attempt to use Supplyline where Landlock is disabled or the host kernel version is prior to 6.12, it will fail to run.

## What does Supplyline do?
The Supplyline service aims to identify cases of supply-chain related malicious payloads and reconstruct them into artifacts which can be analyzed by existing services. Currently Supplyline only focuses on supporting MSBuild script files, with the goal to expand in the future.

Consider a specific scenario where a MSBuild script (.csporj, .sln, .vbproj etc), typically used to define C# or VB.Net Visual Studio projects or solutions, contains a malicious payload which is detonated at build-time. As an example of this, consider the below sample Visual Studio project file:
```
<Project DefaultTargets="testtarget" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <PropertyGroup>
        <testdata1>do</testdata1>
        <testdata2>e</testdata2>
        <testdata3>vi</testdata3>
    </PropertyGroup>
    <PropertyGroup>
        <testdata4>l</testdata3>
        <testdata5>command</testdata4>
    </PropertyGroup>

    <Target Name="testtarget">
        <Exec Command="echo $(testdata1) $(testdata2)$(testdata3)$(testdata4) $(testdata5)" />
    </Target>
</Project>
```

The default build target uses the MSBuild **Exec** Task which is invoked at build-time. In this case, the command is obfuscated using a series of properties to be reconstructed by the MSBuild evaluation processes prior to execution.

The Supplyline service will process MSBuild scripts such as this and evaluates contained Exec tasks, dumping them for further processing and analysis.

## Security Considerations
Under the hood, Supplyline orchestrates the Microsoft Build Project Evaluator to evaluate the Exec tasks and dump reconstructed Exec tasks. Supplyline takes steps to minimize security risks, including wrapping the evaluator with Landlock, however there is some risk and exposure via the Evaluator. Specifically, via Property Functions, code execution can occur during the Project Evaluation stage, although MSBuild restricts this to using an allowlist to prevent side-effects and mitigate security concerns. For more information, refer to: https://devblogs.microsoft.com/visualstudio/msbuild-property-functions/

While Supplyline uses Landlock to sandbox the MSBuild Project Evaluator and the MSBuild Evaluator allow-lists Property Functions, Supplyline can and should be layered with additional containerization. Supplyline should be executed in a containerized environment with minimal permissions.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Supplyline \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-supplyline

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Supplyline

Ce service d'Assemblyline permet d'identifer et d'extraire les paquets malicieux dissimulés dans les chaînes de production.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Supplyline \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-supplyline

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
