# from your repo root
docker build -t ghcr.io/YOURORG/openstack-appcred:1.0.0 -f docker/Dockerfile .
docker push ghcr.io/YOURORG/openstack-appcred:1.0.0



# Assuming you have a local clouds.yaml next to your terminal
kubectl -n my-namespace create secret generic openstack-clouds \
  --from-file=clouds.yaml=./clouds.yaml