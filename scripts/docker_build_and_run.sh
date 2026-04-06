echo "Building the Docker image..."
docker build -t agentrology-env:latest -f Dockerfile .

echo "Checking for existing containers..."
if [ "$(docker ps -aq -f name=agentrology-container)" ]; then
  echo "Stopping and removing existing container..."
  docker stop agentrology-container
  docker rm agentrology-container
fi

echo ""
echo "Running the Docker container..."
docker run -it --name agentrology-container -p 8000:8000 agentrology-env:latest
