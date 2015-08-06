# Volatility attributeht plugin

This plugin searches a memory dump for evidence of the Hacking Team Galileo Remote Control System (RCS), and attempts to attribute the infection to particular Hacking Team client.

The 'elite' level implant maps a region of shared memory using a 7-alphanumeric character name in order to prevent the installation of lower-level implants. This shared memory section is fairly unique, and can be detected using a Regex.

In addition, the list of watermarks for Hacking Team clients was leaked, allowing an attempt at attribution to be made by matching the watermark to a client installation.


For more information, see the blog post here: https://www.4armed.com/blog/memory-forensics-detecting-galileo-rcs-windows

##How-to

The plugin is straightforward to use. The folder where the plugin is located should be passed on to Volatility using the `--plugins=` parameter.

volatility --plugins=volatility-attributeht --profile=WinXPSP2x86 -f test.raw attributeht

