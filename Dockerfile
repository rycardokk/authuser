FROM adoptopenjdk:11-jre-hotspot
LABEL authors="daysechaveslemos"

VOLUME /tmp
ARG JAR_FILE=/target/authuser.jar
COPY ${JAR_FILE} app.jar
WORKDIR /app
CMD ["java", "-cp", "app.jar", "com.ead.authuser.AuthuserApplication"]
