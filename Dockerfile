# Dockerfile

FROM ruby:3.1.4

WORKDIR /code
COPY . /code

RUN apt-get update && apt-get upgrade -y && apt-get install -y yarnpkg
RUN mkdir -p public/vendor
RUN cp .env.example .env
RUN bundle install
RUN yarnpkg install

EXPOSE 4567

CMD ["bundle", "exec", "rackup", "--host", "0.0.0.0", "-p", "4567"]
