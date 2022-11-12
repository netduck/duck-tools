/*
 *
 *      Channel Hopper
 *
 */
#ifndef CHHOP_H
#define CHHOP_H

int channel_hopping(
                char*   iface,
                double  channel /* channel or freq */
                );
                
int is_root(void);
#endif /* CHHOP_H */
