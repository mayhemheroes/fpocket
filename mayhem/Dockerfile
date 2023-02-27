FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libnetcdf-dev libqhull-dev clang

COPY . /repo
WORKDIR /repo
RUN make -j8 
RUN rm /repo/obj/*main.o

RUN LD_LIBRARY_PATH=plugins/LINUXAMD64/molfile clang obj/*.o src/qhull/src/qvoronoi/qvoronoi.o src/qhull/src/qconvex/qconvex.o -o bin/fpocket -lm -Lplugins/LINUXAMD64/molfile plugins/LINUXAMD64/molfile/libmolfile_plugin.a -lstdc++ /repo/mayhem/fuzz_remove_path.cpp -fsanitize=fuzzer,address src/qhull/lib/libqhullstatic.a -I /repo/headers/ -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/bin/fpocket /
COPY --from=builder /fuzz /fuzz_remove_path
