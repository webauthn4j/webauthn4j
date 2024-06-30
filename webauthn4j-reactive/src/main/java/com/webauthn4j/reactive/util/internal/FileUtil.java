package com.webauthn4j.reactive.util.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.CompletionHandler;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class FileUtil {

    private FileUtil(){}

    public static CompletionStage<byte[]> load(Path path){
        return new FileLoader(path).load();
    }


    private static class FileLoader{

        private final Path path;
        private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> completableFuture = new CompletableFuture<>();
        private int position = 0;

        private FileLoader(Path path){
            this.path = path;
        }

        private CompletableFuture<byte[]> load(){
            try {
                AsynchronousFileChannel asynchronousFileChannel = AsynchronousFileChannel.open(path);
                read(asynchronousFileChannel);
                return completableFuture.whenComplete((__, e)-> {
                    try {
                        asynchronousFileChannel.close();
                    } catch (IOException ex) {
                        throw new UncheckedIOException(ex);
                    }
                });
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        private void read(AsynchronousFileChannel asynchronousFileChannel){
            int bufferSize = 1024;
            ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
            asynchronousFileChannel.read(buffer, position, buffer, new CompletionHandler<>() {
                @Override
                public void completed(Integer result, ByteBuffer attachment) {
                    try{
                        byteArrayOutputStream.write(attachment.array(), 0, result);
                        position += result;
                        if(result == bufferSize){
                            read(asynchronousFileChannel);
                        }
                        else {
                            completableFuture.complete(byteArrayOutputStream.toByteArray());
                        }
                    }
                    catch (RuntimeException e){
                        completableFuture.completeExceptionally(e);
                    }
                }
                @Override
                public void failed(Throwable e, ByteBuffer attachment) {
                    completableFuture.completeExceptionally(e);
                }
            });
        }
    }

}
