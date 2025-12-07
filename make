#!/bin/bash

go build cmd/doas.go

sudo chown root:root doas
sudo chmod u+s doas
