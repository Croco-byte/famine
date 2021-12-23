# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: user42 <user42@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2021/12/13 13:19:21 by user42            #+#    #+#              #
#    Updated: 2021/12/23 11:30:21 by user42           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = Famine

LD = ld
NASM = nasm

SRCS =	$(addsuffix .asm, $(addprefix srcs/linux_x64/, famine))

OBJS = ${SRCS:.asm=.o}

all:		$(NAME)

$(NAME):	$(OBJS)
			$(LD) -o $(NAME) $(OBJS)

%.o:%.asm
				$(NASM) -f elf64 -i srcs/linux_x64/ $< -o $@

clean:
				rm -f $(OBJS)

fclean:
				rm -f $(OBJS)
				rm -f $(NAME)

re:				fclean all

.PHONY:			all clean fclean re
