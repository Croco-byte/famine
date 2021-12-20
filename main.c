#include <stdio.h>

# define PF_X			(1 << 0)

int	main(void)
{
	int	n = 70;
	if (n & PF_X)
		return (1);
	return (0);
}
