# Use servercore base image
# can usre full windws base image
# IOT and nanoserver images wont work.

FROM mcr.microsoft.com/windows/servercore:ltsc2019
#FROM mcr.microsoft.com/windows:2004

# Create folders for Application
# Not strictly necessary since you can use
# full path in entry point
RUN mkdir C:\MyApp
COPY Win64/Debug/webapp.exe C:/MyApp/

# Not strictly needed needed since
# entry point has full path
WORKDIR C:/MyApp

# Not strictly needed needed since no other
# app within container is communicating with webapp.exe
# tcp is default but we put it here anyway.
EXPOSE 5200/tcp
EXPOSE 5200/udp

# Use CMD if you want to override the 
# default process in the run command
#ENTRYPOINT ["webapp.exe", "0.0.0.0:5200"]

# Use ENTRYPOINT if you don't intend
# to override the  default process in
# the run command
CMD ["webapp.exe", "0.0.0.0:5200"]


