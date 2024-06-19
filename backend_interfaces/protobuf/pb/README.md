# Protobuf Files

The protobuf files define the marshaller for the backend_protobuf.c. The
resulting C/H files are generated on demand and should be maintained in the
git repo as they are relatively stable.

## Modify *.proto Files

After modification of *.proto files, remove the associated *.c and *.h files.
During the next make run, they are re-generated.
