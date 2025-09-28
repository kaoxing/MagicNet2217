FROM openjdk:21
LABEL authors="kaoxing"

EXPOSE 8001

ARG JAR_FILE=Server-1.0.jar

ADD target/${JAR_FILE} /app.jar

ENTRYPOINT ["java","-jar","/app.jar"]

