package ghidra_yara;

import java.util.Iterator;

public class IterableHelper {

    // Method to convert Iterator to Iterable
    public static <T> Iterable<T> toIterable(Iterator<T> iterator) {
        return () -> iterator;
    }
}
