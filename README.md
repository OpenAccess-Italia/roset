<p align="center">
  <img src="https://github.com/rose-tool/roset/assets/26346836/d58a736b-ea99-4929-a8c6-04eb47364fdd">
</p>

## What is it?
**ROuting SEcurity Tool (ROSE-T)** is a network router configuration checker.

ROSE-T was born in October 2022 from an idea of [Antonio Prado](https://www.prado.it) as a research object for a PhD thesis at the University of Chieti-Pescara in Italy.
The thesis focuses on the security of routing policies to the Internet of network operators. The goal is the implementation of a method capable of verify the configurations of devices in use within Autonomous Systems (AS) also using logical formalisms applied to data extracted from sources authoritative and reliable (Regional Internet Registry and route-collectors).

The first disclosure of ROSE-T, under another name (RS4LK), was made during an "ITNOG on the road" meeting on April 19, 2023 in Pisa, Italy. The [slides](https://www.prado.it/wp-content/uploads/Routing-Security-for-lazy-kids.pdf) show an initial outline of the work in collaboration with researcher [Mariano Scazzariello](https://github.com/Skazza94). After months of effort, scholar [Tommaso Caiazzi](https://github.com/tcaiazzi) also joined the project, and today it has resulted in a software product based on a method that places logical formalism alongside emulation tools.

ROSE-T allows to ensure that a certain router configuration is MANRS-compliant to the [Network Operator Guidelines](https://www.manrs.org/netops/).

Specifically, ROSE-T performs the check for validating the following actions of MANRS:
- Action 1: **Filtering** -> Prevent propagation of incorrect routing information.
- Action 2: **Anti-Spoofing** -> Prevent packets with spoofed source IP address from entering or leaving the network.
- Action 4: **Global Information** -> Network operators must publicly document their routing policies, ASNs and prefixes.

Action 3 cannot be validated automatically since it implies to verify contact information of the candidate.

It leverages __[Kathará](https://github.com/KatharaFramework/Kathara)__ to emulate a virtual network scenario in which the router **realistically interacts** with providers and customers.

**WARNING**: The current version is still for demonstration purposes, and it is not intended to be used in production.

## ROSE-T Presentations
- Mariano Scazzariello presented ROSE-T at RIPE87 in Rome (December 1st 2024):
  - Presentation and Slides: https://ripe87.ripe.net/archives/video/1262/
- The ROSE-T team presented the tool in one of the "Between 0x2 Nerds" podcast episodes, hosted by Jeff Tantsura and Jeff Doyle:
  - YouTube podcast episode: https://www.youtube.com/watch?v=DLpz0mpRWCM
- Tommaso Caiazzi presented ROSE-T at Fiber Telecom Wholesale Winery Tour 2024 (March 21st 2024)
  - Slides: https://www.wholesaletours.it/2024/wwt/speakers/caiazzi.html

## How does it work?

<p align="center">
    <img src="images/steps.png" alt="ROSE-T Steps" width="50%" />
</p>

### Step 1: Gather Candidate Information
In this step the system checks the `Global Information` of the candidate (Action 4 of MANRS), validating the public information.

To do so, ROSE-T verifies:
1. That the networks announced to transit are in the IRR Entry.
2. That the networks in the IRR Entry are announced to transits.

### Step 2: Parse the Configuration
In this step, ROSE-T parses the required information from the vendor configuration (using a custom parser).
Mainly, it extracts interfaces' information (names and IP addresses) and BGP sessions.

### Step 3: Analyze the Configuration
In this step ROSE-T analyzes the parsed configuration to reconstruct the neighbours relationships.
It integrates the information from the IRRs and a RIB dump to infer the topology and understand the relationships.

### Step 4: Emulate the Minimal Network Topology
In this step the system uses the computed information to build a minimal network topology to be emulated.
To power the emulation, ROSE-T leverages on Kathará. The candidate router will use the original configuration/vendor software, while other ASes are emulated as a single router running FRRouting.

### Step 5: Verify Compliance to MANRS
In this step the system leverages on the emulated environment to verify Action 3 and Action 4 of MANRS.

**Filtering (Action 1): "Ensure the correctness of your own announcements and those from your customers to adjacent networks"**

For each customer:
  1. Select non-overlapping subnet and announce it to the candidate router.
  2. Wait that BGP converges.
  3. Check the provider's received routes using the FRR control plane.

<p align="center">
    <img src="images/filtering.png" alt="ROSE-T Filtering Check" width="50%" />
</p>

**Anti-Spoofing (Action 2): "Enable source address validation for at least single-homed stub customer networks, their own end-users, and infrastructure"**

For each provider:
  1. The system creates a client in the provider's AS.
  2. Assign IPs (v4/v6) to each created client.
  3. Send the spoofed ICMP packet.
  4. Check if the spoofed packet leaves the candidate AS.

<p align="center">
    <img src="images/spoofing.png" alt="ROSE-T Anti-Spoofing Check" width="50%" />
</p>

## Supported Vendor Routers
Currently, ROSE-T supports the following vendor routers:
- **Juniper VMX** (>=18.2) through a [hellt/vrnetlab](https://github.com/hellt/vrnetlab) VM embedded in a Docker container.
  - We use a custom version of the VM, which `.patch` files are located in the `vrnet_patches` folder.
  - **Note**: Currently, we only support __flat__ configurations.
- **Cisco IOS XR** (>=7.9.2) using the official [XRd Control Plane](https://software.cisco.com/download/home/286331236/type/280805694) Docker image.
  - You need to properly configure the host machine before running the XRd container. See [this tutorial](https://xrdocs.io/virtual-routing/tutorials/2022-08-22-setting-up-host-environment-to-run-xrd/) for more information.
    - Particularly, you have to increase the `fs.inotify.max_user_instances` and `fs.inotify.max_user_watches` to at least `64000`:
      ```bash
        sysctl -w fs.inotify.max_user_instances=64000
        sysctl -w fs.inotify.max_user_watches=64000
      ```
- **MikroTik RouterOS** (>=7.16) through a [hellt/vrnetlab](https://github.com/hellt/vrnetlab) VM embedded in a Docker container.
  - We use a custom version of the VM, which `.patch` files are located in the `vrnet_patches` folder.
  - **Note**: Currently, we only support __non-terse__ configurations (i.e., do not `export` with the `terse` parameter).
- **FRRouting (FRR)** (>=9.1) using the official [kathara/frr](https://github.com/KatharaFramework/kathara-docker) Docker image.
  - FRR can be used as the candidate router configuration.
  - The candidate router runs the original FRR configuration, while other ASes are emulated using FRR.
  - **Note**: The configuration must be in standard FRR format (like the output of `show running-config` in vtysh).
  - You can optionally provide a startup script to be executed after FRR daemons start. This is useful for applying custom iptables rules for anti-spoofing testing. Specify the script path in the `startup_script_path` field of the candidate JSON file.

We plan to extend the support to additional vendors in the future.

## Hands-on

### Requirements

1. Docker
2. Kathará
3. Python 3.10 or higher

### Pre-Requisites

1. Download the requisites:
```
python3 -m pip install -r src/requirements.txt
```

2. You need an updated MRT RIB dump. You can download the latest dump from [RRC00](https://data.ris.ripe.net/rrc00/) or generate one from an existing Kathará lab.
Now, enter the `resources` directory, and run the `load_mrt.py` script:
```
cd resources
python3 load_mrt.py <TABLE_DUMP_RIB_FILE> <OUTPUT_FILE.db>
```
The command requires two positional parameters:
- `<TABLE_DUMP_RIB_FILE>` is the RIB dump in `.gz` format.
- `<OUTPUT_FILE.db>` is the name of the output SQLite3 database (stored in the `resources` directory). By default, the name is `rib_latest.db`.

### Candidate Configuration File

ROSE-T takes as input a JSON file describing the candidate AS. The file specifies the ASN, the relationships file, the RIB dump, and one or more routers belonging to the candidate AS.

```json
{
  "local_as": 101,
  "relationships": "relationships.json",
  "rib_dump": "rib.db",
  "routers": [
    {
      "name": "c1",
      "vendor": "frr",
      "config_path": "c1.frr",
      "startup_script_path": "c1_startup.txt"
    },
    {
      "name": "c2",
      "vendor": "frr",
      "config_path": "c2.frr"
    }
  ]
}
```

The supported fields are:
- `local_as`: The ASN of the candidate Autonomous System.
- `relationships`: Path to the relationships JSON file (see below).
- `rib_dump`: Path to the SQLite3 database generated by `load_mrt.py`.
- `routers`: A list of routers belonging to the candidate AS. Each router entry supports the following fields:
  - `name`: A unique name for the router within the candidate AS.
  - `vendor`: The vendor of the router. Supported values are `frr`, `junos`, `iosxr`, `routeros`.
  - `docker_image`: Name of the docker image to use
  - `config_path`: Path to the router configuration file.
  - `startup_script_path` *(optional)*: Path to a startup script executed after the router starts. Useful for applying custom iptables rules.

A typical candidate directory looks like this:

```
CandidateAS/
├── c1.frr
├── c1_startup.txt
├── c2.frr
├── c3.frr
├── candidate.json
├── relationships.json
└── rib.db
```

### Run a Test

To run the verification:
```bash
sudo ../.venv/bin/python3 test_as_candidate.py \
    --as_config <PATH_TO_CANDIDATE_JSON> \
    --file <PATH_TO_OUTPUT_FILE>
```

The supported parameters are:
- `--as_config` / `-c` *(required)*: Path to the candidate JSON configuration file.
- `--file` *(optional)*: Path to the output file where results will be written.
- `--rib_dump` *(optional)*: Path to the SQLite3 RIB dump database. Overrides the value specified in the candidate JSON. Defaults to `resources/rib_latest.db` if not specified in either place.
- `--relationships` *(optional)*: Path to a local relationships JSON file. Overrides the value specified in the candidate JSON.
- `--exclude_checks` *(optional)*: Comma-separated list of checks to skip. Supported values are `information`, `spoofing`, and `leak`.
- `--result-level` *(optional)*: Minimum result level to include in the output. Supported values are `WARNING`, `SUCCESS`, and `ERROR`.
- `--name` *(optional)*: Name for the network scenario. Defaults to `as_<local_as>`.
- `--debug` *(optional)*: Enable debug logging output.

The test can take up to a few minutes, depending on your hardware. Ensure that you have a good amount of RAM and nested virtualization enabled.

**NOTE**: ROSE-T works only on Docker on Linux or WSL2, and it is compatible only with the `amd64` architecture (Apple Silicon is not supported).

## Build the patched `vrnetlab` images

1. Clone the [hellt/vrnetlab](https://github.com/hellt/vrnetlab) repository, you can clone it inside the root directory of ROSE-T:
```bash
git clone https://github.com/hellt/vrnetlab
```

2. Apply the patches located in the `vrnet_patches` folder. If you cloned `vrnetlab` in the root folder of ROSE-T:
```bash
cd vrnetlab
git apply ../vrnet_patches/vrnet.patch
git apply ../vrnet_patches/<os_name>.patch
```
Where `<os_name>.patch` is the name of the patch file.

3. Now, to build the image, copy the VM file provided by the vendor (e.g., `.tar.gz` for Juniper, or `.vmdk` for RouterOS) inside the corresponding OS folder (e.g. `vmx`) and run `make`. The process will take few minutes.

## Customizations

### Using a local relationships file instead of RIPE DB

For testing or lab environments where RIPE DB relationships are not available, you can provide a local relationships file via the `relationships` field in the candidate JSON (or via `--relationships` on the command line). The file must be in JSON format:

```json
{
  "AS101": {
    "AS100": "peer",
    "AS102": "peer",
    "AS103": "customer",
    "AS104": "provider"
  }
}
```

Valid relationship values are: `provider`, `customer`, `peer`.

#### Specifying transit ASes

The relationships file also supports an optional `as_rules` section to declare which providers are used as transit by a given AS. This information is used by ROSE-T during the Global Information verification to correctly assess the routing policies of the candidate and its neighbors.

```json
{
  "AS3": {
    "AS1": "provider",
    "AS2": "provider",
    "AS4": "customer",
    "AS5": "customer"
  },
  "as_rules": {
    "AS3": {
      "transits": [2, 4]
    }
  }
}
```

In this example, AS3 uses AS2 and AS4 as transit providers. The `transits` field accepts a list of ASNs.