/* Copyright (c) 2019, Matthew Finkel.
 * Copyright (c) 2019, Hans-Christoph Steiner.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef ORG_TORPROJECT_JNI_TORSERVICE_H
#define ORG_TORPROJECT_JNI_TORSERVICE_H

#include <jni.h>

/*
 * Class:     org_torproject_jni_TorService
 * Method:    createTorConfiguration
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_org_torproject_jni_TorService_createTorConfiguration
(JNIEnv *, jobject);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    mainConfigurationSetCommandLine
 * Signature: ([Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL
Java_org_torproject_jni_TorService_mainConfigurationSetCommandLine
(JNIEnv *, jobject, jobjectArray);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    mainConfigurationSetupControlSocket
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_org_torproject_jni_TorService_mainConfigurationSetupControlSocket
(JNIEnv *, jobject);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    mainConfigurationFree
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_org_torproject_jni_TorService_mainConfigurationFree
(JNIEnv *, jobject);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    apiGetProviderVersion
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_apiGetProviderVersion
(JNIEnv *, jobject);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    runMain
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_org_torproject_jni_TorService_runMain
(JNIEnv *, jobject);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    torFreeAll
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_org_torproject_jni_TorService_torFreeAll
(JNIEnv *, jobject);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    prepareFileDescriptor
 */
JNIEXPORT jobject JNICALL
Java_org_torproject_jni_TorService_prepareFileDescriptor
(JNIEnv *env, jclass, jstring);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    libeventVersion
 */
JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_libeventVersion
(JNIEnv *env, jobject obj);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    opensslVersion
 */
JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_opensslVersion
(JNIEnv *env, jobject obj);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    zlibVersion
 */
JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_zlibVersion
(JNIEnv *env, jobject obj);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    zstdVersion
 */
JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_zstdVersion
(JNIEnv *env, jobject obj);

/*
 * Class:     org_torproject_jni_TorService
 * Method:    lzmaVersion
 */
JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_lzmaVersion
(JNIEnv *env, jobject obj);

#endif /* !defined(ORG_TORPROJECT_JNI_TORSERVICE_H) */
