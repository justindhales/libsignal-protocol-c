#include <stdio.h>
#include <check.h>
#include <pthread.h>

#include "protocol.h"
#include "signal_protocol_types.h"
#include "signal_protocol.h"
#include "session_record.h"
#include "session_cipher.h"
#include "ratchet.h"
#include "test_common.h"

signal_context* global_context;
pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

void exit_if_error(int result, int expected) {
    if (result != expected) {
        exit(1);
    }
}

void initialize_sessions_v3(session_state *alice_state, session_state *bob_state)
{
    int result = 0;

    /* Generate Alice's identity key */
    ec_key_pair *alice_identity_key_pair = 0;
    result = curve_generate_key_pair(global_context, &alice_identity_key_pair);
    exit_if_error(result, 0);

    ratchet_identity_key_pair *alice_identity_key = 0;
    result = ratchet_identity_key_pair_create(&alice_identity_key,
            ec_key_pair_get_public(alice_identity_key_pair),
            ec_key_pair_get_private(alice_identity_key_pair));
    exit_if_error(result, 0);
    SIGNAL_UNREF(alice_identity_key_pair);

    /* Generate Alice's base key */
    ec_key_pair *alice_base_key = 0;
    result = curve_generate_key_pair(global_context, &alice_base_key);
    exit_if_error(result, 0);

    /* Generate Alice's pre-key */
    ec_key_pair *alice_pre_key = alice_base_key;
    SIGNAL_REF(alice_base_key);

    /* Generate Bob's identity key */
    ec_key_pair *bob_identity_key_pair = 0;
    result = curve_generate_key_pair(global_context, &bob_identity_key_pair);
    exit_if_error(result, 0);

    ratchet_identity_key_pair *bob_identity_key = 0;
    result = ratchet_identity_key_pair_create(&bob_identity_key,
            ec_key_pair_get_public(bob_identity_key_pair),
            ec_key_pair_get_private(bob_identity_key_pair));
    exit_if_error(result, 0);
    SIGNAL_UNREF(bob_identity_key_pair);

    /* Generate Bob's base key */
    ec_key_pair *bob_base_key = 0;
    result = curve_generate_key_pair(global_context, &bob_base_key);
    exit_if_error(result, 0);

    /* Generate Bob's ephemeral key */
    ec_key_pair *bob_ephemeral_key = bob_base_key;
    SIGNAL_REF(bob_base_key);

    /* Create Alice's parameters */
    alice_signal_protocol_parameters *alice_parameters = 0;
    result = alice_signal_protocol_parameters_create(&alice_parameters,
            /* our_identity_key       */ alice_identity_key,
            /* our_base_key           */ alice_base_key,
            /* their_identity_key     */ ratchet_identity_key_pair_get_public(bob_identity_key),
            /* their_signed_pre_key   */ ec_key_pair_get_public(bob_base_key),
            /* their_one_time_pre_key */ 0,
            /* their_ratchet_key      */ ec_key_pair_get_public(bob_ephemeral_key));
    exit_if_error(result, 0);

    /* Create Bob's parameters */
    bob_signal_protocol_parameters *bob_parameters = 0;
    result = bob_signal_protocol_parameters_create(&bob_parameters,
            /* our_identity_key     */ bob_identity_key,
            /* our_signed_pre_key   */ bob_base_key,
            /* our_one_time_pre_key */ 0,
            /* our_ratchet_key      */ bob_ephemeral_key,
            /* their_identity_key   */ ratchet_identity_key_pair_get_public(alice_identity_key),
            /* their_base_key       */ ec_key_pair_get_public(alice_base_key));
    // exit_if_error(result, 0);

    /* Initialize the ratcheting sessions */
    result = ratcheting_session_alice_initialize(alice_state, alice_parameters, global_context);
    exit_if_error(result, 0);
    result = ratcheting_session_bob_initialize(bob_state, bob_parameters, global_context);
    exit_if_error(result, 0);

    /* Unref cleanup */
    SIGNAL_UNREF(alice_identity_key);
    SIGNAL_UNREF(alice_base_key);
    SIGNAL_UNREF(alice_pre_key);
    SIGNAL_UNREF(bob_identity_key);
    SIGNAL_UNREF(bob_base_key);
    SIGNAL_UNREF(bob_ephemeral_key);
    SIGNAL_UNREF(alice_parameters);
    SIGNAL_UNREF(bob_parameters);
}

void create_sessions(session_record** alice_session_record, session_record** bob_session_record) {
    int result = 0;

    result = session_record_create(alice_session_record, 0, global_context);
    exit_if_error(result, 0);

    result = session_record_create(bob_session_record, 0, global_context);
    exit_if_error(result, 0);

    initialize_sessions_v3(
        session_record_get_state(*alice_session_record), 
        session_record_get_state(*bob_session_record)
    );
}

void decrypt_and_compare_messages(session_cipher *cipher, signal_buffer *ciphertext, signal_buffer *plaintext)
{
    int result = 0;

    /* Create a signal_message from the ciphertext */
    signal_message *index_message_deserialized = 0;
    result = signal_message_deserialize(&index_message_deserialized,
            signal_buffer_data(ciphertext),
            signal_buffer_len(ciphertext),
            global_context);
    exit_if_error(result, 0);

    /* Decrypt the message */
    signal_buffer *index_plaintext = 0;
    result = session_cipher_decrypt_signal_message(cipher, index_message_deserialized, 0, &index_plaintext);
    exit_if_error(result, 0);

    /* Compare the messages */
    // Print only the bytes of the message (the buffer might be in units of block sizes)
    fprintf(stderr, "%.*s\n", (int) signal_buffer_len(index_plaintext), signal_buffer_data(index_plaintext));
    exit_if_error(signal_buffer_compare(index_plaintext, plaintext), 0);
    fprintf(stderr, "Decrypted message matches original\n");

    /* Cleanup */
    SIGNAL_UNREF(index_message_deserialized);
    signal_buffer_free(index_plaintext);
}

void test_lock(void *user_data) {
    pthread_mutex_lock(&global_mutex);
}

void test_unlock(void *user_data) {
    pthread_mutex_unlock(&global_mutex);
}

void setup() {
    int result = 0;
    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    result = signal_context_create(&global_context, 0);
    exit_if_error(result, 0);
    signal_context_set_log_function(global_context, test_log);

    setup_test_crypto_provider(global_context);

    result = signal_context_set_locking_functions(global_context, test_lock, test_unlock);
    exit_if_error(result, 0);
}

void teardown() {
    signal_context_destroy(global_context);

    pthread_mutex_destroy(&global_mutex);
    pthread_mutexattr_destroy(&global_mutex_attr);
}

void setup_store_context(signal_protocol_store_context **context, signal_context *global_context) {
    int result = 0;

    signal_protocol_store_context *store_context = 0;
    result = signal_protocol_store_context_create(&store_context, global_context);
    exit_if_error(result, 0);

    setup_test_session_store(store_context);
    setup_test_pre_key_store(store_context);
    setup_test_signed_pre_key_store(store_context);
    setup_test_identity_key_store(store_context, global_context);
    setup_test_sender_key_store(store_context, global_context);

    *context = store_context;
}

void decompose_wire(char* alice_plaintext, size_t alice_plaintext_len) {
    int result = 0;
    session_record* alice_session_record = NULL;
    session_record* bob_session_record = NULL;

    create_sessions(&alice_session_record, &bob_session_record);

    signal_protocol_address alice_address = {
            "+14159999999", 12, 1
    };

    signal_protocol_address bob_address = {
            "+14158888888", 12, 1
    };

    /* Create the test data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_store_context(&alice_store, global_context);

    signal_protocol_store_context *bob_store = 0;
    setup_store_context(&bob_store, global_context);

    /* Store the two sessions in their data stores */
    result = signal_protocol_session_store_session(alice_store, &bob_address, alice_session_record);
    exit_if_error(result, 0);
    result = signal_protocol_session_store_session(bob_store, &alice_address, bob_session_record);
    exit_if_error(result, 0);

    /* Create two session cipher instances */
    session_cipher *alice_cipher = 0;
    result = session_cipher_create(&alice_cipher, alice_store, &bob_address, global_context);
    exit_if_error(result, 0);

    session_cipher *bob_cipher = 0;
    result = session_cipher_create(&bob_cipher, bob_store, &alice_address, global_context);
    exit_if_error(result, 0);

    /* Encrypt a test message from Alice */
    // static const char alice_plaintext[] = "This is Alice's message";
    // size_t alice_plaintext_len = sizeof(alice_plaintext) - 1;

    ciphertext_message *alice_message = 0;
    // signal_buffer* ciphertext = 0;
    result = session_cipher_encrypt(alice_cipher, (uint8_t *)alice_plaintext, alice_plaintext_len, &alice_message);
    exit_if_error(result, 0);

    /* Serialize the test message to create a fresh instance */
    signal_buffer *alice_message_serialized = ciphertext_message_get_serialized(alice_message);
    if (alice_message_serialized == 0) {
        exit(1);
    }

    fprintf(stderr, "\nSerialized message:\n");
    size_t len = signal_buffer_len(alice_message_serialized);
    uint8_t* data = signal_buffer_data(alice_message_serialized);
    for(size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", data[i]);
    }
    fprintf(stderr, "\n\n");

    /* Have Bob decrypt the test message */
    signal_buffer *alice_plaintext_buffer = signal_buffer_create((uint8_t*) alice_plaintext, alice_plaintext_len);
    decrypt_and_compare_messages(bob_cipher, alice_message_serialized, alice_plaintext_buffer);

    SIGNAL_UNREF(alice_session_record);
    SIGNAL_UNREF(bob_session_record);
}

int main(int argc, char *argv[]) {
    printf("Decompose ciphertext_message struct\n");

    if(argc != 2) {
        fprintf(stderr, "Usage: %s \"<plaintext>\"\n", argv[0]);
        exit(1);
    }

    char* message = argv[1];
    size_t message_len = strlen(message);

    printf("Original message (0x%02lx):\n%s\n\n", message_len, message);

    setup();
    decompose_wire(message, message_len);
    teardown();
}