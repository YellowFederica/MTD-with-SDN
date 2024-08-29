FROM debian:bullseye-slim


ENV DEBIAN_FRONTEND noninteractive
RUN apt update
RUN apt install apt-transport-https iputils-ping traceroute iproute2 -y

# Download Ryu source code and install
RUN apt-get update 
RUN    apt install python3-pip git -y
RUN apt install gcc python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev -y
RUN git clone https://github.com/faucetsdn/ryu.git
RUN cd ryu; pip install .
#RUN pip install eventlet==0.33.0
#RUN pip install dnspython==2.2.1

# Show ryu-manager version
RUN apt install net-tools iproute2 iputils-ping traceroute -y
RUN apt install procps -y
RUN ryu-manager --version
#RUN nohup ryu-manager simple_switch_13.py &
#CMD ["ryu-manager", "simple_switch_13.py", ">>","log.txt"]
