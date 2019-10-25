#!/bin/bash
set -x
# commented out; hangs!
#psql -p 5002 -d $PGDATABASE -U $PGUSERNAME -c "vacuum (full,analyze, verbose) storefiles;"
psql -p 5002 -d $PGDATABASE -U $PGUSERNAME -c "vacuum (full,analyze, verbose) binary_status;"
psql -p 5002 -d $PGDATABASE -U $PGUSERNAME -c "vacuum (full,analyze, verbose) sensor_registrations;"
psql -p 5002 -d $PGDATABASE -U $PGUSERNAME -c "vacuum (full,analyze, verbose) vt_write_events;"
