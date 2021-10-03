import { States } from "./States"

// simple state machine as a linked list
export class State {
    private state : States;
    private nextState: State;
    private prevState: State;

    constructor(s: States) {
        this.state = s;
    }

    public setNextState(s: State) : State {
        this.nextState = s;
        s.setPrevState(this);
        return s;
    }

    public setPrevState(s: State) {
        this.prevState = s;
    }

    public currentState() : States {
        return this.state;
    }

    public getNextState() : State {
        return this.nextState;
    }
}