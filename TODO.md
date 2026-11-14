* Logging
  * Destinations
     * File
     * Application
     * Vector?
     * Clickhouse?
  * per-vhost and global
  * error and access
  * something akin to Apache's mod_log_forensic
  * Customizable log formats
* Configuration API
* Internal statistics tracking and display (ala apache-status or nginx's admin socket)
* Connection limiting
* Swarm mode
  * Utilizing Redis to detect fleet-wide abuse