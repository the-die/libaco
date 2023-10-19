# libaco

## Symmetric coroutine and Asymmetric coroutine

[Revisiting Coroutines](https://www.inf.puc-rio.br/~roberto/docs/MCC15-04.pdf)

__Symmetric coroutine__ facilities provide a single control-transfer operation that allows coroutines to explicitly pass control between themselves. __Asymmetric coroutine__ mechanisms (more commonly denoted as __semi-symmetric or semi coroutines__) provide two control-transfer operations: one for invoking a coroutine and one for suspending it, the latter returning control to the coroutine invoker. While __symmetric coroutines__ operate at the same hierarchical level, an __asymmetric coroutine__ can be regarded as subordinate to its caller, the relationship between them being somewhat similar to that between a called and a calling routine.

## Description

`main co`

`non-main co`

`standalone non-main co`

![thread_model_3](img/thread_model_3.png)

![proof_0](img/proof_0.png)
