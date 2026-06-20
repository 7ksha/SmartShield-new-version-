.. image:: /images/smartshield_logo.png
    :align: center

smartshield
============================

The tool is available on GitHub `here <https://github.com/stratosphereips/StratosphereLinuxIPS/tree/master>`_.

**smartshield** is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. smartshield was designed to focus on targeted attacks, to detect of command and control channelsi, and to provide good visualisation for the analyst. smartshield is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, smartshield highlights suspicious behaviour and connections that needs to be deeper analyzed.

This documentation gives an overview how smartshield works, how to use it and how to help. To be specific, that table of contents goes as follows:


- **Installation**. Instructions to install smartshield in a Docker and in a computer. See :doc:`Installation <installation>`.

- **Usage**. Instructions and examples how to run smartshield with different type of files and analyze the traffic using smartshield and its GUI Kalipso. See :doc:`Usage <usage>`.

- **Detection modules**. Explanation of detection modules in smartshield, types of input and output. See :doc:`Detection modules <detection_modules>`.

- **Architecture**. Internal architecture of smartshield (profiles, timewindows), the use of Zeek and connection to Redis. See :doc:`Architecture <architecture>`.

- **Training with your own data**. Explanation on how to re-train the machine learning system of smartshield with your own traffic (normal or malicious).See :doc:`Training <training>`.

- **Detections per Flow**. Explanation on how smartshield works to make detections on each flow with different techniques. See :doc:`Flow Alerts <flowalerts>`.

- **Exporting**. The exporting module allows smartshield to export to Slack and STIX servers. See :doc:`Exporting <exporting>`.

- **smartshield in Action**. Example of using smartshield to analyze different PCAPs See :doc:`smartshield in action <smartshield_in_action>`.

- **Contributing**. Explanation how to contribute to smartshield, and instructions how to implement new detection module in smartshield. See :doc:`Contributing <contributing>`.

- **Create a new module**. Step by step guide on how to create a new smartshield module See :doc:`Create a new module <create_new_module>`.

- **Code documentation**. Auto generated smartshield code documentation See :doc:`Code docs <code_documentation>`.

- **Datasets**. The folder `dataset` contains some testing datasets for you to try. See :doc:`Datasets <datasets>`.




.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: smartshield
   :glob:

   self
   installation
   usage
   architecture
   detection_modules
   flowalerts
   features
   training
   exporting
   P2P
   fides_module
   create_new_module
   datasets
   immune/Immune
   smartshield_in_action
   FAQ
   contributing
   code_documentation
   related_repos
   visualisation
