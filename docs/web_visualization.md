# smartshield Web Visualization

To see the alerts of smartshield in a visual way, the methodology is the following

1. smartshield must be configured to export the alerts in STIX format to a TAXII server, as explained in [exporting](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html).
2. You need to install a TAXII server (available in the smartshieldWeb submodule folder). See its README.md
3. Use the program `smartshieldWeb` that is availbale in the StratosphereWeb submodule that reads from the TAXII server.

All the setup does not consume many resources, so you can run this visualization even in small servers like a Raspberry Pi. However, by having many smartshield exporting to the same server you can centralize the visualization of many sensors in a unique location, probably with more hardware if needed.