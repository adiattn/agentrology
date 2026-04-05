echo "Building the Docker image..."
docker build -t agentrology-env:latest -f server/Dockerfile .

echo ""
echo "Running the Docker container..."
docker run -d --name agentrology-container -p 8000:8000 agentrology
