package com.opp.todo.interfaces;

import java.util.zip.DataFormatException;

public interface TodoImageUtil {

    byte[] compress(byte[] data) throws DataFormatException;
    byte[] deCompress(byte[] data) throws DataFormatException;
}
