package com.example.vulnapp;

public class Example {

    private Chain chain;
    private Ops ops;
    private Object router1, validator, endrouter;

    // EXPECT: order_scan — required call `call2` is missing from the sequence.
    public void exampleFunction() {
        ops.call1();
        ops.call3();
    }

    // EXPECT: order_scan — chain arguments are out of order (endrouter before router1).
    public void register() {
        chain.root().add(endrouter).add(validator).add(router1);
    }

    interface Ops {
        void call1();
        void call2();
        void call3();
    }

    interface Chain {
        Chain root();
        Chain add(Object handler);
    }
}
