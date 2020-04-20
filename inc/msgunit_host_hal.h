#ifndef MSGUNIT_HOST_HAL_H
#define MSGUNIT_HOST_HAL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the messaging unit. Should be called only once at startup.
 * @return 0 if OK, or negative number if fail
 */
int mu_init(void);
/**
 * Function for sending the data from host core to sentinel core.
 * @param data to be send
 * @param size of data
 * @return number of sent bytes, -1 in case of error
 */
int mu_send_data_h(uint32_t *data, size_t size);
/**
 * Function for receiving the message from sentinel core on host core.
 * @param pointer to data buffer where to store the message
 * @param max_length max size of the message/buffer
 * @return number of received bytes, -1 in case of error
 */
int mu_receive_data_h(uint32_t *data, size_t max_size);

#ifdef __cplusplus
}
#endif

#endif /* MSGUNIT_HOST_HAL_H */
