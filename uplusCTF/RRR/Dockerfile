FROM ubuntu@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97

ENV user rrr
ENV chall_port 44040

RUN apt-get update
RUN apt-get -y install socat

RUN adduser -u 4040 $user

ADD ./deploy/flag /home/$user/flag
ADD ./deploy/prob /home/$user/prob

RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/prob

RUN chmod 755 /home/$user/prob
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
EXPOSE $chall_port
CMD socat TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:./prob,stderr