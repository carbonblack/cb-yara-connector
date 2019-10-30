#!/bin/bash
psql -p 5002 -d cb -c "vacuum (full,analyze, verbose) storefiles;"
psql -p 5002 -d cb -c "vacuum (full,analyze, verbose) binary_status;"
psql -p 5002 -d cb -c "vacuum (full,analyze, verbose) sensor_registrations;"
psql -p 5002 -d cb -c "vacuum (full,analyze, verbose) vt_write_events;"
