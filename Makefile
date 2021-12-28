# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: user42 <user42@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2021/12/13 13:19:21 by user42            #+#    #+#              #
#    Updated: 2021/12/28 11:17:13 by user42           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = Famine

LD = ld
NASM = nasm

SRCS =	$(addsuffix .asm, $(addprefix srcs/famine/, famine))

OBJS = ${SRCS:.asm=.o}

all:		$(NAME)

$(NAME):	$(OBJS)
			$(LD) -o $(NAME) $(OBJS)

%.o:%.asm
			$(NASM) -f elf64 -i srcs/famine/ $< -o $@

strife:
			nasm -f elf64 -i srcs/strife/ srcs/strife/strife.asm -o srcs/strife/strife.o && ld srcs/strife/strife.o -o Strife

clean:
				rm -f $(OBJS)

fclean:
				rm -f $(OBJS)
				rm -f $(NAME)
				rm -f Strife
				rm -f srcs/strife/strife.o

re:				fclean all

.PHONY:			all clean fclean re
