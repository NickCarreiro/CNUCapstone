#!/bin/bash

PORT=8000
# Ensure that the AWS Security group reflects outgoing port

HOST=0.0.0.0
#Ensure that you're pointing to an accessible endpoint (0.0.0.0 by default)

python3 -m uvicorn app.main:app --reload --host 0.0.0.0 --port $PORT
echo "Server started successfully at $PORT"
